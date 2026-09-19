"""Read-only curl probes; not browser CORS verification. Uses public test addresses."""
import concurrent.futures, datetime, json, subprocess
eth='0x9858EfFD232B4033E47d90003D41EC34EcaEda94'
sol='HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk'
tron='TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH'
plans=[]
for name,url,checks in [('ethereum','https://eth.llamarpc.com',[('eth_chainId',[]),('eth_getBalance',[eth,'latest'])]),('bsc','https://bsc-dataseed.binance.org',[('eth_chainId',[]),('eth_getBalance',[eth,'latest'])]),('solana','https://api.mainnet-beta.solana.com',[('getGenesisHash',[]),('getBalance',[sol,{'commitment':'confirmed'}])])]:
    for method,params in checks: plans.append((name,url,{'jsonrpc':'2.0','id':1,'method':method,'params':params}))
plans.extend([('tron','https://api.trongrid.io/wallet/getblockbynum',{'num':0}),('tron','https://api.trongrid.io/wallet/getaccount',{'address':tron,'visible':True})])
def run(plan):
    chain,url,body=plan
    p=subprocess.run(['curl','--silent','--show-error','--max-time','25','--fail-with-body','-H','Content-Type: application/json','-H','Origin: http://127.0.0.1:4174','--data',json.dumps(body),url],capture_output=True,text=True)
    try: response=json.loads(p.stdout)
    except ValueError: response=p.stdout[:500]
    return dict(chain=chain,url=url,request=body,exitCode=p.returncode,response=response,error=p.stderr[:500])
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(run,plans))
print(json.dumps(dict(observedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),mode='Public curl reads; browser CORS not established',results=results),indent=2))
