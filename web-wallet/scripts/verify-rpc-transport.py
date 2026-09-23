"""Read-only curl probes; not browser CORS verification. Uses public test addresses."""
import concurrent.futures, datetime, json, subprocess, threading, time
eth='0x9858EfFD232B4033E47d90003D41EC34EcaEda94'
sol='HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk'
tron='TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH'
plans=[]
for name,url,checks in [('ethereum','https://ethereum-rpc.publicnode.com',[('eth_chainId',[]),('eth_getBalance',[eth,'latest'])]),('bsc','https://bsc-dataseed.binance.org',[('eth_chainId',[]),('eth_getBalance',[eth,'latest'])]),('solana','https://public.rpc.solanavibestation.com',[('getGenesisHash',[]),('getBalance',[sol,{'commitment':'confirmed'}])])]:
    for method,params in checks: plans.append((name,url,{'jsonrpc':'2.0','id':1,'method':method,'params':params}))
for mint in ['Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v']:
    plans.append(('solana', 'https://public.rpc.solanavibestation.com', {'jsonrpc':'2.0','id':1,'method':'getTokenAccountsByOwner','params':[sol,{'mint':mint},{'encoding':'jsonParsed','commitment':'confirmed'}]}))
solana_lock=threading.Lock()
plans.extend([('tron','https://api.trongrid.io/wallet/getblockbynum',{'num':0}),('tron','https://api.trongrid.io/wallet/getaccount',{'address':tron,'visible':True})])
def run(plan):
    if plan[0] == 'solana':
        with solana_lock:
            time.sleep(1.2)
            return request(plan)
    return request(plan)
def request(plan):
    chain,url,body=plan
    p=subprocess.run(['curl','--silent','--show-error','--max-time','25','--fail-with-body','-H','Content-Type: application/json','-H','Origin: http://127.0.0.1:4174','--data',json.dumps(body),url],capture_output=True,text=True)
    try: response=json.loads(p.stdout)
    except ValueError: response=p.stdout[:500]
    return dict(chain=chain,url=url,request=body,exitCode=p.returncode,response=response,error=p.stderr[:500])
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(run,plans))
print(json.dumps(dict(observedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),mode='Public curl reads; browser CORS not established',results=results),indent=2))
