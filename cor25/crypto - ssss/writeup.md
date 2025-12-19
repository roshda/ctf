# corCTF 2025 – crypto/alt-shamir

*published: 2025-08-29*

This weekend, I played corCTF 2025 with a few members of Psi Beta Rho at UCLA. One of the crypto challenges I solved was based on a twist on Shamir’s Secret Sharing, specifically [this variant](https://www.zkdocs.com/docs/zkdocs/protocol-primitives/alt-shamir/#moving-away-from-the-constant-term) where the secret isn’t in the constant term of the polynomial.

## Setup

Normally in Shamir’s scheme, the secret is just the constant term of the polynomial:  

```
f(x) = s + a1 x + a2 x^2 + …
```

But here, they used an alternative version:  
```
f(x) = g(x)·x^2 + Sx + c   (mod p)
```

So instead of being f(0), the secret S is the coefficient of x. That means the secret can be recovered as the derivative at 0.

## Thought process

At first I was confused because Shamir interpolation should work regardless of which coefficient is the secret. But after rereading the docs from ZKDocs, I realized this was exactly the variant they described. 

This makes our solve simple. We query the server with enough x-values, collect the corresponding y’s = f(x) and use Lagrange interpolation to reconstruct the polynomial.  
Finally we get the coefficient of x (compute the derivative).  

I ended up implementing this directly with a set of Lagrange basis weights for evaluation at 0. Basically, we precompute weights `w_j` such that:  

```
S = Σ w\_j \* y\_j
````

---

## Solve script

```python
from pwn import *

p = 2255 - 19
host, port = "ctfi.ng", 31555
r = remote(host, port)
XS = [1,2,3,4,5,6,7] + [p-1,p-2,p-3,p-4,p-5,p-6,p-7]

def inv(a):
    return pow(a, p-2, p)

# precompute Lagrange weights for evaluation at 0
WS = []
for j, xj in enumerate(XS):
    w = inv(xj)
    for m, xm in enumerate(XS):
        if m == j: continue
        w = (w * ((-xm) % p) * inv((xj - xm) % p)) % p
    WS.append(w)

# query server for y values
ys = []
for x in XS:
    r.sendline(str(x).encode())
    while True:
        line = r.recvline()
        if not line: continue
        try:
            y = int(line.strip())
            ys.append(y % p)
            break
        except:
            pass

# compute secret as weighted sum
S = 0
for w, y in zip(WS, ys):
    S = (S + w * y) % p

r.sendline(str(S).encode())
print(r.recvall().decode())
````

## Flag

```
corctf{ill_come_up_with_a_good_flag_later_maybe}
```