#!/usr/bin/env python3
"""Disposable namespace calibration of the aggregate helper (Linux root only)."""
import json,os,socket,statistics,subprocess,sys,time,uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

ROOT=Path(__file__).resolve().parents[1]

def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,**kw).stdout

def peer():
    # Separate listeners permit two simultaneous streams in one rate class.
    import threading
    def serve(port):
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('10.203.0.2',port));s.listen()
            while True:
                c,_=s.accept()
                with c:
                    c.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
                    while True:
                        b=c.recv(65536)
                        if not b:break
                        if port==29000:c.sendall(b)
    for p in (29000,29001,29002):threading.Thread(target=serve,args=(p,),daemon=True).start()
    time.sleep(300)

def probe(kind):
    if kind=='rtt':
        values=[]
        with socket.create_connection(('10.203.0.2',29000)) as s:
            s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            for _ in range(25):
                t=time.monotonic_ns();s.sendall(b'x');assert s.recv(1)==b'x';values.append((time.monotonic_ns()-t)/1e6)
        print(json.dumps({'median_ms':statistics.median(values),'samples_ms':values}));return
    count=16*1024*1024
    def send(port):
        with socket.create_connection(('10.203.0.2',port)) as s:
            b=b'x'*65536
            for _ in range(count//len(b)):s.sendall(b)
            s.shutdown(socket.SHUT_WR)
            # FIN acknowledgement and EOF wait until the server consumed bytes.
            assert s.recv(1)==b''
    start=time.monotonic()
    with ThreadPoolExecutor(2) as p:list(p.map(send,(29001,29002)))
    elapsed=time.monotonic()-start
    print(json.dumps({'parallel_streams':2,'payload_bytes':count*2,'seconds':elapsed,'aggregate_mbps':count*2*8/elapsed/1e6}))

def main():
    if len(sys.argv)>1 and sys.argv[1]=='peer':peer();return
    if len(sys.argv)>1 and sys.argv[1]=='probe':probe(sys.argv[2]);return
    if sys.platform!='linux' or os.geteuid()!=0:raise SystemExit('Linux root required')
    token=uuid.uuid4().hex[:8];a,b='dlga'+token,'dlgb'+token
    server=None; created=[];shaped=[];result={'calibration_scope':'two disposable Linux network namespaces; no cloud network qualification'}
    def inside(ns,args,**kw):return run(['ip','netns','exec',ns]+args,**kw)
    def helper(ns,request):
        reply=json.loads(inside(ns,[sys.executable,str(ROOT/'scripts/linux_egress.py')],input=json.dumps(request)))
        if not reply['ok']:raise RuntimeError(reply['error'])
        return reply['result']
    try:
        for ns in (a,b):run(['ip','netns','add',ns]);created.append(ns)
        run(['ip','link','add','dlga0','netns',a,'type','veth','peer','name','dlgb0','netns',b])
        for ns,dev,ip in ((a,'dlga0','10.203.0.1/30'),(b,'dlgb0','10.203.0.2/30')):
            inside(ns,['ip','addr','add',ip,'dev',dev]);inside(ns,['ip','link','set',dev,'up']);inside(ns,['ip','link','set','lo','up'])
        server=subprocess.Popen(['ip','netns','exec',b,sys.executable,__file__,'peer'],start_new_session=True)
        time.sleep(.3)
        result['baseline']=json.loads(inside(a,[sys.executable,__file__,'probe','rtt']))
        for ns,dev,ip,ports in ((a,'dlga0','10.203.0.2',[29000,29001,29002]),(b,'dlgb0','10.203.0.1',[29000,29001,29002])):
            nonce=uuid.uuid4().hex;shaped.append((ns,nonce))
            helper(ns,{'action':'configure','nonce':nonce,'interface':dev,'peers':[{'ip':ip,'port':p} for p in ports],
                       'local_ports':ports,'delay_ms':10,'rate_mbps':100})
        result['shaped']=json.loads(inside(a,[sys.executable,__file__,'probe','rtt']))
        result['fanout']=json.loads(inside(a,[sys.executable,__file__,'probe','bulk']))
        result['before_clear']=[helper(ns,{'action':'status','nonce':nonce}) for ns,nonce in shaped]
        result['cleanup']=[helper(ns,{'action':'clear','nonce':nonce}) for ns,nonce in shaped];shaped=[]
        result['restored']=json.loads(inside(a,[sys.executable,__file__,'probe','rtt']))
        added=result['shaped']['median_ms']-result['baseline']['median_ms']
        assert 17<=added<=35,(added,result)
        assert 70<=result['fanout']['aggregate_mbps']<=110,result['fanout']
        assert result['restored']['median_ms']<result['baseline']['median_ms']+5
        result['passed']=True;print(json.dumps(result,indent=2))
    finally:
        for ns,nonce in shaped:
            try:helper(ns,{'action':'clear','nonce':nonce})
            except Exception as e:print('helper cleanup failure: '+str(e),file=sys.stderr)
        if server:
            import signal
            os.killpg(server.pid,signal.SIGTERM);server.wait(timeout=5)
        for ns in reversed(created):run(['ip','netns','del',ns])

if __name__=='__main__':main()
