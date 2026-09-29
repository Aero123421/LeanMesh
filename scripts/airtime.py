"""Payload-bit lower bounds, not an RF simulator or measured latency predictor."""
import argparse,json,math

def estimate(hops:int,payload:int,rate:int=250000)->dict:
    if not 1<=hops<=40 or not 0<=payload<=4096:raise ValueError('hops 1..40 and payload 0..4096')
    cap=136-2*hops
    if payload<=cap:parts=[payload]
    else:
        step=((cap-40)//16)*16
        parts=[40+min(step,payload-i) for i in range(0,payload,step)]
    data_bytes=sum(114+2*hops+p for p in parts)*hops
    ack_bytes=52*len(parts)*hops
    # One compact transfer-bitmap return is possible; end receipt/control may fragment.
    return {'hops':hops,'application_bytes':payload,'phy_bps_assumption':rate,
            'single_frame_application_bytes':cap,'outbound_frames_per_edge':len(parts),
            'data_plus_hop_accept_bytes_over_all_edges':data_bytes+ack_bytes,
            'serialized_payload_bits_lower_bound_ms':round((data_bytes+ack_bytes)*8/rate*1000,3),
            'excluded':['802.11 headers','PHY preambles','MAC ACK','CCA/backoff','hidden terminals',
                        'end receipt and fragment bitmap return','processing','queued traffic','all retries'],
            'caution':'Summed edge occupancy lower bound assuming serialized use, NOT wall-clock latency or RF coverage.'}
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--hops',type=int,default=20);a.add_argument('--payload',type=int,default=96);n=a.parse_args()
    print(json.dumps(estimate(n.hops,n.payload),ensure_ascii=False,indent=2))
