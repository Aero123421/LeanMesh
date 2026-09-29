"""Executable LM1 wire contract fixtures, NOT a Mesh SDK or EDHOC implementation.
All keys/seeds are public test material. No networking or device writes.
"""
from __future__ import annotations
import hashlib, hmac, json, struct, sys
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT=Path(__file__).resolve().parents[1]
LINK=struct.Struct('>2sBBIIQHBB'); ROUTE=struct.Struct('>HHBBBBII')
END=struct.Struct('>IQ16sHBBQH'); FRAG=struct.Struct('>HHHBB32s')
FLEET=bytes(range(16)); DOMAIN=bytes(range(16,32))

def _head(major:int,n:int)->bytes:
    if not 0<=n<2**64: raise ValueError('CBOR integer/length out of range')
    if n<24:return bytes([major*32+n])
    if n<256:return bytes([major*32+24,n])
    if n<65536:return bytes([major*32+25])+n.to_bytes(2,'big')
    if n<2**32:return bytes([major*32+26])+n.to_bytes(4,'big')
    return bytes([major*32+27])+n.to_bytes(8,'big')

def cbor(x:Any)->bytes:
    """RFC8949 core deterministic subset: no floats, tags, indefinite lengths."""
    if x is None:return b'\xf6'
    if isinstance(x,bool):return b'\xf5' if x else b'\xf4'
    if isinstance(x,int):return _head(0,x) if x>=0 else _head(1,-1-x)
    if isinstance(x,bytes):return _head(2,len(x))+x
    if isinstance(x,str):
        b=x.encode('utf-8');return _head(3,len(b))+b
    if isinstance(x,(list,tuple)):return _head(4,len(x))+b''.join(cbor(y) for y in x)
    if isinstance(x,dict):
        items=sorted((cbor(k),cbor(v)) for k,v in x.items())
        return _head(5,len(items))+b''.join(k+v for k,v in items)
    raise TypeError(type(x).__name__)

def decode(data:bytes)->Any:
    pos=0
    def take(n:int)->bytes:
        nonlocal pos
        if n<0 or pos+n>len(data):raise ValueError('truncated CBOR')
        b=data[pos:pos+n];pos+=n;return b
    def item(depth:int=0)->Any:
        if depth>16:raise ValueError('CBOR nesting')
        first=take(1)[0]; major=first>>5; ai=first&31
        if major==7 and ai in (20,21,22):return {20:False,21:True,22:None}[ai]
        if ai<24:n=ai
        elif ai in (24,25,26,27):
            width={24:1,25:2,26:4,27:8}[ai];n=int.from_bytes(take(width),'big')
            if n<({1:24,2:256,4:65536,8:2**32}[width]):raise ValueError('nonminimal CBOR')
        else:raise ValueError('unsupported/indefinite CBOR')
        if major==0:return n
        if major==1:return -1-n
        if major==2:return take(n)
        if major==3:return take(n).decode('utf-8')
        if major==4:
            if n>4096:raise ValueError('array capacity')
            return [item(depth+1) for _ in range(n)]
        if major==5:
            if n>128:raise ValueError('map capacity')
            out={};prev=None
            for _ in range(n):
                st=pos;k=item(depth+1);raw=data[st:pos]
                if prev is not None and raw<=prev:raise ValueError('map order/duplicate')
                prev=raw
                if not isinstance(k,(int,str,bytes)) or k in out:raise ValueError('map key')
                out[k]=item(depth+1)
            return out
        raise ValueError('unsupported CBOR major')
    x=item()
    if pos!=len(data):raise ValueError('trailing CBOR')
    return x

def pubkey(scalar:int)->dict[int,Any]:
    # PUBLIC TEST-ONLY scalar, never used by product code.
    p=ec.derive_private_key(scalar,ec.SECP256R1()).public_key().public_numbers()
    return {1:2,-1:1,-2:p.x.to_bytes(32,'big'),-3:p.y.to_bytes(32,'big')}

def did(scalar:int)->bytes:return hashlib.sha256(cbor(pubkey(scalar))).digest()
def context(purpose:int,a:int,b:int)->bytes:
    return cbor(['LM1',purpose,FLEET,DOMAIN,did(a),did(b),1,1,1,1,
                 hashlib.sha256(b'credential-test-'+bytes([a])).digest(),
                 hashlib.sha256(b'credential-test-'+bytes([b])).digest()])

def record_key(seed:bytes,ctx:bytes,purpose:int,direction:int)->tuple[bytes,bytes]:
    ch=hashlib.sha256(ctx).digest()
    prk=hmac.new(ch,seed,hashlib.sha256).digest()
    info=b'LM1-RECORD'+bytes([purpose,direction])+ch
    okm=hmac.new(prk,info+b'\x01',hashlib.sha256).digest()[:20]
    return okm[:16],okm[16:]

def frame(hops:int)->dict[str,Any]:
    if not 1<=hops<=40:raise ValueError('hops')
    path=list(range(3,3+hops));final=path[-1]
    payload=bytes((i*17+7)%256 for i in range(136-2*hops))
    lc=context(1,2,3);ecx=context(2,2,final)
    # Different synthetic Exporter outputs for each fixture; no reused GCM key/nonce.
    ls=hashlib.sha256(f'PUBLIC-TEST-ONLY-link-{hops}'.encode()).digest()
    es=hashlib.sha256(f'PUBLIC-TEST-ONLY-end-{hops}'.encode()).digest()
    lk,lp=record_key(ls,lc,1,0);ek,ep=record_key(es,ecx,2,0)
    mid=struct.pack('>QQ',1,hops)
    eh=END.pack(0x10203040,1,mid,7,1,5,120000,len(payload))
    ea=b'LM1-END'+hashlib.sha256(ecx).digest()+struct.pack('>I',1)+eh
    er=eh+AESGCM(ek).encrypt(ep+struct.pack('>Q',1),payload,ea)
    route=ROUTE.pack(2,final,hops,0,hops,0,1,1)
    plain=route+b''.join(struct.pack('>H',x) for x in path)+er
    lh=LINK.pack(b'LM',1,3,int.from_bytes(DOMAIN[:4],'big'),0x50607080,1,len(plain),1,0)
    packet=lh+AESGCM(lk).encrypt(lp+struct.pack('>Q',1),plain,lh+hashlib.sha256(lc).digest())
    ih=hashlib.sha256(cbor([did(2),did(final),DOMAIN,7,1,0,1,1,120000,payload])).hexdigest()
    return dict(name=f'full-frame-{hops}-hop',hops=hops,link_context_hex=lc.hex(),
        end_context_hex=ecx.hex(),link_exporter_test_seed_hex=ls.hex(),end_exporter_test_seed_hex=es.hex(),
        packet_hex=packet.hex(),payload_hex=payload.hex(),packet_bytes=len(packet),
        intent_hash=ih,packet_sha256=hashlib.sha256(packet).hexdigest())

def open_frame(v:dict[str,Any],packet:bytes|None=None)->bytes:
    packet=bytes.fromhex(v['packet_hex']) if packet is None else packet
    if len(packet)>250 or len(packet)<114:raise ValueError('frame size')
    lh=packet[:24];magic,ver,kind,hint,sid,ctr,bl,flags,res=LINK.unpack(lh)
    if (magic,ver,kind,flags,res)!=(b'LM',1,3,1,0) or sid==0 or ctr==0:raise ValueError('link header')
    if len(packet)!=24+bl+16:raise ValueError('link length')
    lc=bytes.fromhex(v['link_context_hex']);ecx=bytes.fromhex(v['end_context_hex'])
    lk,lp=record_key(bytes.fromhex(v['link_exporter_test_seed_hex']),lc,1,0)
    p=AESGCM(lk).decrypt(lp+struct.pack('>Q',ctr),packet[24:],lh+hashlib.sha256(lc).digest())
    origin,final,n,index,budget,res,term,revision=ROUTE.unpack(p[:16])
    if not 1<=n<=40 or index>=n or budget!=n-index or res!=0:raise ValueError('route fields')
    path=list(struct.unpack('>'+'H'*n,p[16:16+2*n]))
    ectx=decode(ecx)
    # Fixture's address-to-full-Identity mapping is scalar(address); product uses membership map.
    if ectx[4]!=did(origin) or ectx[5]!=did(final):raise ValueError('route Identity/session mismatch')
    if len(set([origin]+path))!=n+1 or final!=path[-1] or any(x in (0,65535) for x in path):raise ValueError('not a simple path')
    off=16+2*n;eh=p[off:off+42]
    esid,ectr,mid,port,rkind,eflags,expires,length=END.unpack(eh)
    if not esid or not ectr or port in(0,65535) or rkind!=1 or eflags&0xe0 or eflags&3==3:raise ValueError('end header')
    if len(p)!=off+42+length+16:raise ValueError('end length')
    ek,ep=record_key(bytes.fromhex(v['end_exporter_test_seed_hex']),ecx,2,0)
    return AESGCM(ek).decrypt(ep+struct.pack('>Q',ectr),p[off+42:],b'LM1-END'+hashlib.sha256(ecx).digest()+struct.pack('>I',term)+eh)

def fragments(payload:bytes,hops:int,ih:bytes)->list[bytes]:
    if not 0<len(payload)<=4096 or len(ih)!=32:raise ValueError('fragment limits')
    quantum=((136-2*hops-FRAG.size)//16)*16
    if quantum<16:raise ValueError('MTU too small')
    cls=0 if len(payload)<=512 else 1
    return [FRAG.pack(len(payload),off,len(payload[off:off+quantum]),1,cls,ih)+payload[off:off+quantum]
            for off in range(0,len(payload),quantum)]

def reassemble(chunks:list[bytes])->bytes:
    if not chunks:raise ValueError('empty')
    total,off,n,kind,cl,ih=FRAG.unpack(chunks[0][:40])
    if not 0<total<=4096 or kind not in(1,2,4) or cl not in(0,1,2):raise ValueError('metadata')
    b=bytearray(total);seen=bytearray(total)
    for c in chunks:
        t,o,k,ty,cs,h=FRAG.unpack(c[:40])
        if (t,ty,cs,h)!=(total,kind,cl,ih) or len(c)!=40+k or o%16 or k==0 or o+k>total or (o+k<total and k%16):raise ValueError('fragment mismatch')
        for i,z in enumerate(c[40:],o):
            if seen[i] and b[i]!=z:raise ValueError('fragment conflict')
            b[i]=z;seen[i]=1
    if not all(seen):raise ValueError('incomplete')
    return bytes(b)

def cose_fixture()->dict[str,Any]:
    private=ec.derive_private_key(1,ec.SECP256R1())
    protected=cbor({1:-7,4:did(1)})
    data=[did(2),FLEET,bytes(16),DOMAIN,bytes.fromhex('33'*32),0,1,bytes.fromhex('44'*16),0,bytes.fromhex('55'*16),bytes.fromhex('66'*32)]
    payload=cbor([3,1,bytes.fromhex('77'*16),DOMAIN,1,did(1),data])
    signing=cbor(['Signature1',protected,b'LM1-CONTROL',payload])
    signature=private.sign(signing,ec.ECDSA(hashes.SHA256()))
    rr,ss=utils.decode_dss_signature(signature);raw=rr.to_bytes(32,'big')+ss.to_bytes(32,'big')
    return {'test_only':True,'private_scalar_public_test_value':1,'cose_key_hex':cbor(pubkey(1)).hex(),
            'device_id_hex':did(1).hex(),'protected_hex':protected.hex(),'payload_hex':payload.hex(),
            'sig_structure_hex':signing.hex(),'signature_raw_hex':raw.hex(),
            'cose_sign1_hex':(b'\xd2'+cbor([protected,{},payload,raw])).hex()}

def check_cose(v:dict[str,Any])->None:
    encoded=bytes.fromhex(v['cose_sign1_hex'])
    if encoded[:1]!=b'\xd2':raise ValueError('COSE tag18')
    protected,unprotected,payload,raw=decode(encoded[1:])
    if unprotected!={} or decode(protected)!={1:-7,4:bytes.fromhex(v['device_id_hex'])}:raise ValueError('COSE headers')
    key=decode(bytes.fromhex(v['cose_key_hex']))
    pub=ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2],'big'),int.from_bytes(key[-3],'big'),ec.SECP256R1()).public_key()
    signing=cbor(['Signature1',protected,b'LM1-CONTROL',payload])
    pub.verify(utils.encode_dss_signature(int.from_bytes(raw[:32],'big'),int.from_bytes(raw[32:],'big')),signing,ec.ECDSA(hashes.SHA256()))
    if hashlib.sha256(cbor(key)).hexdigest()!=v['device_id_hex']:raise ValueError('DeviceID hash')

def generate()->None:
    x={'notice':'PUBLIC SYNTHETIC TEST DATA ONLY. AES/COSE contract vectors; not EDHOC/RF qualification.',
       'frames':[frame(h) for h in [1,3,20,40]],'cose_sign1':cose_fixture()}
    (ROOT/'tests/golden.json').write_text(json.dumps(x,indent=2)+'\n')
if __name__=='__main__':
    if sys.argv[1:]==['--generate']:generate()
    else:print('Use --generate only when intentionally replacing the reference fixtures.')
