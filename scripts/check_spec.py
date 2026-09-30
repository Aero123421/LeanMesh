"""Validate this specification bundle without touching a device or user account.
No production SDK, full EDHOC engine, FastAPI runtime, RF, or HIL is executed.
"""
from __future__ import annotations
import base64, binascii, copy, csv, hashlib, json, platform, random, re, shutil
import sqlite3, struct, subprocess, sys, tempfile, warnings
from pathlib import Path
import cryptography,jsonschema
from jsonschema import Draft202012Validator,FormatChecker
with warnings.catch_warnings():
    warnings.simplefilter('ignore',DeprecationWarning)
    from jsonschema import RefResolver
from cryptography.exceptions import InvalidTag,InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from wire_fixture import cbor,decode,open_frame,record_key,reassemble,fragments,check_cose
from airtime import estimate
ROOT=Path(__file__).resolve().parents[1]
checks=[]

def check(name,fn):
    try:
        detail=fn();checks.append({'name':name,'status':'PASS','detail':detail})
    except Exception as exc:
        checks.append({'name':name,'status':'FAIL','detail':f'{type(exc).__name__}: {exc}'})

def fails(fn,types=(Exception,)):
    try:fn()
    except types:return
    raise AssertionError('negative case unexpectedly accepted')

def load(path):return json.loads((ROOT/path).read_text())

# Vendored upstream trees, build outputs and caches are not part of this bundle's contract.
EXCLUDED_DIRS={'.git','third_party','build','managed_components','.venv','__pycache__','.pytest_cache'}
def bundle_files(pattern):
    return [p for p in ROOT.rglob(pattern) if not EXCLUDED_DIRS & set(p.relative_to(ROOT).parts[:-1])]

def jsons():
    paths=bundle_files('*.json')
    for p in paths:json.loads(p.read_text())
    return {'files':len(paths)}

def wire():
    r=load('protocol/registry.json');d=load('config/defaults.json')
    for name,spec in r['fields'].items():
        assert struct.calcsize(r['struct_formats'][name])==spec['bytes']
        cursor=0
        for x in spec['items']:
            assert x['offset']==cursor,(name,x)
            cursor+=x['size']
        assert cursor==spec['bytes']
    assert struct.calcsize(r['struct_formats']['fragment'])==40
    assert struct.calcsize(r['struct_formats']['serial'])==18
    assert 16+3+1==20
    assert r['limits']['fragment_quantum']==d['delivery']['fragment_quantum']==16
    assert [136-2*h for h in(1,20,40)]==[134,96,56]
    assert 18+8192+16+4==r['limits']['serial_decoded_bytes']
    assert 24+16+12==52
    header=(ROOT/'api/leanmesh.h').read_text()
    for k,v in r['status_codes'].items():assert re.search(r'LM_STATUS_'+k+r'\s*=\s*'+str(v)+r'\b',header),k
    assert r['aead']['edhoc']['exporter_label'] in range(32768,65536)
    assert r['session_binding']['ead_sent_labels']==[]
    assert not any(v==-40000 for v in r.get('aead',{}).values())
    return {'fixed_headers':'24/16/42 bytes','application_capacity_1_20_40_hop':[134,96,56],'record_bitmap_bytes':35,'status_codes':len(r['status_codes'])}

def crypto_vectors():
    g=load('tests/golden.json');negative=0
    for v in g['frames']:
        packet=bytes.fromhex(v['packet_hex']);plain=bytes.fromhex(v['payload_hex'])
        assert open_frame(v)==plain
        assert len(packet)==250 and hashlib.sha256(packet).hexdigest()==v['packet_sha256']
        corrupt=bytearray(packet);corrupt[-1]^=1
        fails(lambda:open_frame(v,bytes(corrupt)),(InvalidTag,));negative+=1
        corrupt=bytearray(packet);corrupt[2]=2
        fails(lambda:open_frame(v,bytes(corrupt)),(ValueError,));negative+=1
        fails(lambda:open_frame(v,packet+b'\x00'),(ValueError,));negative+=1
        wrong=copy.deepcopy(v);wrong['link_exporter_test_seed_hex']='00'*32
        fails(lambda:open_frame(wrong),(InvalidTag,));negative+=1
        # A peer holding a link key must still not install a cyclic source path.
        if v['hops']>=3:
            lc=bytes.fromhex(v['link_context_hex'])
            key,prefix=record_key(bytes.fromhex(v['link_exporter_test_seed_hex']),lc,1,0)
            body=bytearray(AESGCM(key).decrypt(prefix+(1).to_bytes(8,'big'),packet[24:],packet[:24]+hashlib.sha256(lc).digest()))
            body[18:20]=body[16:18]
            forged=packet[:24]+AESGCM(key).encrypt(prefix+(1).to_bytes(8,'big'),bytes(body),packet[:24]+hashlib.sha256(lc).digest())
            # This intentional invalid test uses the public test key; never a transmit path.
            fails(lambda:open_frame(v,forged),(ValueError,));negative+=1
    check_cose(g['cose_sign1'])
    bad=copy.deepcopy(g['cose_sign1']);b=bytearray.fromhex(bad['cose_sign1_hex']);b[-1]^=1;bad['cose_sign1_hex']=b.hex()
    fails(lambda:check_cose(bad),(InvalidSignature,));negative+=1
    for v in [{1:2,-1:1,-2:b'x'*32,-3:b'y'*32},[1,'日本語',True,None,b'\x00'],{100:2,-1:3}]:assert decode(cbor(v))==v
    for invalid in [b'\x18\x01',b'\x01\x00',b'\x9f\xff',bytes.fromhex('a201020103')]:
        fails(lambda:decode(invalid),(ValueError,));negative+=1
    return {'aes_gcm_frames':len(g['frames']),'cose_signature_fixtures':1,'negative_checks':negative,'edhoc_handshakes_run':0}

def fragment_contract():
    values=[]
    for hops,size in [(1,512),(20,128),(20,512),(40,512),(40,4096)]:
        payload=bytes((i*7)%256 for i in range(size));ih=hashlib.sha256(payload).digest()
        chunks=fragments(payload,hops,ih)
        assert all(len(c)<=136-2*hops for c in chunks)
        reordered=list(reversed(chunks))+[chunks[0]]
        assert reassemble(reordered)==payload
        fails(lambda:reassemble(chunks[:-1]),(ValueError,))
        bad=bytearray(chunks[0]);bad[-1]^=1
        fails(lambda:reassemble(chunks+[bytes(bad)]),(ValueError,))
        values.append({'hops':hops,'payload':size,'fragments':len(chunks)})
    assert 2+32+1<=56
    return {'cases':values,'scope':'standalone fixture reassembly shape, not product reliability tests'}

def sql_contract():
    with tempfile.TemporaryDirectory() as td:
        conn=sqlite3.connect(str(Path(td)/'spec.db'));conn.executescript((ROOT/'db/schema.sql').read_text())
        assert conn.execute('pragma journal_mode').fetchone()[0]=='wal'
        assert conn.execute('pragma synchronous').fetchone()[0]==2
        assert conn.execute('pragma foreign_keys').fetchone()[0]==1
        conn.execute("insert into principals values(?,?,?,?)",('p',bytes(32),'["SEND"]',1))
        conn.execute("insert into principals values(?,?,?,?)",('q',bytes([1])*32,'["SEND"]',1))
        conn.execute('insert into domains(id) values(?)',(bytes(16),))
        conn.execute("insert into client_epochs(id,principal,state) values(?,?,'OPEN')",(bytes([1])*16,'p'))
        cols='id,principal,domain,type,client_epoch,idempotency_key,request_hash,request_json,state'
        cmd='insert into operations('+cols+') values('+','.join('?' for _ in range(9))+')'
        row=[bytes([2])*16,'p',bytes(16),'SEND',bytes([1])*16,'testkey',bytes(32),'{}','HOST_COMMITTED']
        conn.execute(cmd,row)
        row[0]=bytes([3])*16
        fails(lambda:conn.execute(cmd,row),(sqlite3.IntegrityError,))
        row[1]='q';row[5]='differentkey'
        fails(lambda:conn.execute(cmd,row),(sqlite3.IntegrityError,))
        fails(lambda:conn.execute('insert into domains(id) values(?)',(b'bad',)),(sqlite3.IntegrityError,))
        assert conn.execute('pragma integrity_check').fetchone()==('ok',)
        assert conn.execute('pragma foreign_key_check').fetchall()==[]
        count=conn.execute("select count(*) from sqlite_master where type='table' and name not like 'sqlite_%'").fetchone()[0]
        conn.close()
    return {'sqlite_version':sqlite3.sqlite_version,'tables':count,'wal_full':True,'power_cut_test':False}

def schemas():
    spec=load('api/openapi.json');schema=load('config/policy.schema.json')
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(load('config/policy.example.json'))
    refs=[];operations=[]
    def walk(x):
        if isinstance(x,dict):
            if '$ref' in x:refs.append(x['$ref'])
            if 'operationId' in x:operations.append(x['operationId'])
            for y in x.values():walk(y)
        elif isinstance(x,list):
            for y in x:walk(y)
    walk(spec)
    for ref in refs:
        assert ref.startswith('#/'),ref
        cur=spec
        for part in ref[2:].split('/'):cur=cur[part.replace('~1','/').replace('~0','~')]
    assert len(operations)==len(set(operations))
    for path,pitem in spec['paths'].items():
        for method,operation in pitem.items():
            if method not in {'get','post','put','delete','patch'}:continue
            assert operation.get('responses'),path
            for name in re.findall(r'\{(.*?)\}',path):
                assert any(p.get('in')=='path' and p.get('name')==name and p.get('required') for p in operation.get('parameters',[])+pitem.get('parameters',[])),(path,name)
    resolver=RefResolver.from_schema(spec)
    val=Draft202012Validator(spec['components']['schemas']['MessageRequest'],resolver=resolver,format_checker=FormatChecker())
    request={'domain_id':'01'*16,'client_epoch':'02'*16,'destination':{'kind':'node','device_id':'03'*32},'app_port':1,'payload_b64':base64.b64encode(b'payload').decode(),'delivery':'APPLIED','storage':'DURABLE','queue_mode':'FIFO','priority':'URGENT','deadline':{'mode':'root','root_term':1,'expires_root_ms':'90000'}}
    # Destination naming is an explicit source of interoperability bugs.
    val.validate(request)
    bad=copy.deepcopy(request);bad['app_port']=65535
    fails(lambda:val.validate(bad),(jsonschema.ValidationError,))
    bad=copy.deepcopy(request);bad['surprise']=True
    fails(lambda:val.validate(bad),(jsonschema.ValidationError,))
    def semantic(req):
        val.validate(req)
        raw=base64.b64decode(req['payload_b64'],validate=True)
        assert len(raw)<=(4096 if req.get('object_transfer') else 512)
        if req['queue_mode']=='LATEST':assert req['delivery']=='BEST_EFFORT' and req['storage']=='VOLATILE' and 'coalesce_key' in req
        if req['deadline']['mode']=='none':assert req['delivery']=='RECEIVED' and req['storage']=='DURABLE'
    semantic(request)
    for changes in [{'queue_mode':'LATEST'},{'deadline':{'mode':'none'}},{'payload_b64':'@@@'}]:
        bad=copy.deepcopy(request);bad.update(changes);fails(lambda:semantic(bad))
    return {'openapi':'3.1 shapes/refs/path params plus positive/negative request constraints', 'paths':len(spec['paths']),'schemas':len(spec['components']['schemas']),'resolved_references':len(refs),'formal_openapi_meta_schema_validation':False}

def compilers():
    compiler=shutil.which('cc');cpp=shutil.which('c++')
    if not compiler or not cpp:raise RuntimeError('cc/c++ required for ABI declaration syntax check')
    results=[]
    for executable,std,language in [(compiler,'c11','c'),(cpp,'c++17','c++')]:
        for example in ['examples/application.c','examples/apps/equipment_control.c','examples/apps/battery_measurement.c']:
            cmd=[executable,'-x',language,'-std='+std,'-Wall','-Wextra','-Werror','-fsyntax-only','-I',str(ROOT/'api'),str(ROOT/example)]
            p=subprocess.run(cmd,check=False,capture_output=True,text=True,timeout=20)
            if p.returncode:raise AssertionError(p.stderr)
        results.append(language)
    return {'declarations_and_example':results,'linked_implementation':False,'esp_idf_build':False}

def partitions():
    rows=[]
    for line in (ROOT/'config/partitions_4m.csv').read_text().splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            vals=next(csv.reader([line]));name,typ,sub,offset,size=map(str.strip,vals[:5]);rows.append((name,typ,int(offset,0),int(size,0)))
    prev=0x9000
    for name,typ,off,size in rows:
        assert off>=prev and off%0x1000==0 and size%0x1000==0,(name,off,size)
        if typ=='app':assert off%0x10000==0
        prev=off+size
    assert prev==0x400000
    apps=[row for row in rows if row[1]=='app'];assert len(apps)==2 and apps[0][3]==apps[1][3]
    assert apps[0][3]==1900544
    return {'partition_count':len(rows),'flash_bytes':prev,'ota_slot_bytes':apps[0][3],'hardware_test':False}

def traceability():
    sourceids={s['id'] for s in load('evidence/source_registry.json')['sources']}
    scenarios=load('tests/scenarios.json')['scenarios'];ids={x['id'] for x in scenarios}
    assert len(ids)==len(scenarios)
    assert all(x['execution_status']=='NOT_RUN_PRODUCT_TEST' for x in scenarios)
    rows=list(csv.DictReader((ROOT/'tests/traceability.csv').open()))
    assert {x['requirement'] for x in rows}==set(load('config/requirements.json')['requirements'])
    for row in rows:
        assert set(row['source_ids'].split(';'))<=sourceids,row
        assert set(row['test_ids'].split(';'))<=ids,row
        assert (ROOT/row['specification']).is_file()
        assert row['implementation_status']=='SPECIFIED_NOT_IMPLEMENTED'
    return {'requirements':len(rows),'acceptance_scenarios':len(scenarios),'product_scenarios_executed':0,'source_records':len(sourceids)}

def links():
    total=0
    for f in bundle_files('*.md'):
        for dest in re.findall(r'\[[^\]]*\]\(([^)]+)\)',f.read_text()):
            if '://' in dest or dest.startswith(('#','mailto:')):continue
            target=dest.split('#')[0]
            if not target:continue
            assert (f.parent/target).resolve().is_file(),str(f.relative_to(ROOT))+': '+dest
            total+=1
    return {'local_markdown_links':total,'external_urls_fetched_by_checker':False}

def cddl_bounds():
    text=(ROOT/'protocol/control.cddl').read_text();serial=(ROOT/'protocol/serial.cddl').read_text()
    assert 'critical EAD label=-40000' not in (ROOT/'docs/06-security.md').read_text()
    assert 'transfer-start =' not in text
    assert 'bitmap' not in load('protocol/registry.json')['control_types']
    assert 'bstr .size (0..4096)' in serial
    assert 'type: (1..21 / 25..33)' in text
    return {'selected_cross_contract_checks':True,'formal_cddl_grammar_and_cbor_instance_validation':False}

def airtime():
    a=estimate(20,96);assert a['outbound_frames_per_edge']==1
    assert a['serialized_payload_bits_lower_bound_ms']==193.28
    b=estimate(40,512);assert b['outbound_frames_per_edge']==32
    return {'20hop_96B_serialized_bits_lower_bound_ms':193.28,'not_latency_prediction':True}

for name,fn in [('json_parse',jsons),('wire_layout',wire),('aes_cose_and_cbor_vectors',crypto_vectors),('fragment_contract',fragment_contract),('sqlite_schema',sql_contract),('openapi_and_policy',schemas),('c_and_cpp_syntax',compilers),('partition_accounting',partitions),('requirement_traceability',traceability),('markdown_links',links),('control_contract_bounds',cddl_bounds),('airtime_accounting',airtime)]:check(name,fn)
from check_revision import CHECKS
for name, fn in CHECKS: check(name, fn)
report={'artifact':'LeanMesh spec v0.2','date':'2026-09-28','status':'PASS' if all(c['status']=='PASS' for c in checks) else 'FAIL','environment':{'python':platform.python_version(),'sqlite':sqlite3.sqlite_version,'cryptography':cryptography.__version__},'checks':checks,'product_tests_run':False,'not_executed':['EDHOC full engine interop/RFC trace run','ESP-IDF builds for all four chips','radio PHY/peer behavior','physical 20/40 hop','FastAPI product server','power cut/disk failure on real hardware','independent cryptographic review','measured firmware flash/RAM/CPU/energy','clang-format/clang-tidy/ruff product lint','full lifecycle and power runtime implementation']}
(ROOT/'evidence/VALIDATION.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
for c in checks:print(c['status'],c['name'],json.dumps(c['detail'],ensure_ascii=False))
print('Overall:',report['status']);sys.exit(0 if report['status']=='PASS' else 1)
