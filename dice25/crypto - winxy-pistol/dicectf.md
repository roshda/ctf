# DiceCTF Quals 2025 - crypto/winxy-pistol

*published: 2025-04-03*

This spring break weekend, I played DiceCTF 2025 Quals with some members of Psi Beta Rho at UCLA. We ended up 3rd in the undergraduate division!

This is a writeup for one of the cryptography challenges I solved, [winxy-pistol](https://github.com/defund/ctf/tree/master/dicectf-quals-2025/winxy-pistol). This challenge came as a direct sequel to vorpal-sword, continuing the RSA-based oblivious transfer. vorpal-sword introduced the basic concept and let us break it via a algebra, but as a challenge winxy-pistol added a fixed RSA key and XOR masking. 


## Setup

This is an interactive choose‑your‑own‑adventure game. At each fork the server presents two encrypted messages — one “live” (“you continue walking. turn to page X.”) and one “die” (“you die of a fever,” etc). This happens 64 times, and only by picking the live message every round do you reach the end and get the flag.

Each round runs a 1‑out‑of‑2 RSA oblivious transfer. The server samples random `x0, x1` and prints them with the public key `(n, e)`. You choose a secret `r`, compute  
```  
v = x_b + rᵉ mod n  
```  
to encode your branch choice `b ∈ {0,1}`, and send `v`.

It then computes  
```  
k0 = (v - x0)**d % n  
k1 = (v - x1)**d % n  
```  
and encrypts the two messages as  
```  
c0 = m0 ⊕ H(k0)  
c1 = m1 ⊕ H(k1)  
```  
Each `k_i` is hashed with SHAKE‑256 into a 64‑byte pad (from a 128‑byte key) and XOR’d with the padded message. 

## What didn’t work anymore

In vorpal-sword we exploited the algebraic properties of RSA. Since the server was using additive masking (c0 = m0 + k0) — we could manipulate the value of v to control k0 and k1. Specifically, by choosing v = (x0 + x1) // 2, we forced k0 = -k1, and therefore:

```
c0 + c1 = m0 + m1
```

Because the messages followed a known structure, it was trivial to recover both.

That no longer worked here. XOR is not linear the way addition is, so we couldn’t collapse the messages together to get their sum or difference. Also there was hash function so we couldn't do algebra. 

However, I realized that all 64 rounds used the same RSA key. That meant if we could ever recreate a key used in one session from another session, we might be able to link things together.

In a standard OT, the receiver chooses v so that only one of the two keys, k0 or k1, becomes something they can work with.

To get both message, if two sessions use the same key (even for just one message), and the server uses the same RSA private key, then H(k) will also repeat. Also, since the masking is just XOR, repeated keys are vulnerable.

We want to set it up so that the key for the second message in one connection could become the key for the first message in another connection by manipulating v. 


## Implementation


1. In our **main connection**, we send v = x0. That forces k0 = 0 so we can instantly decrypt m0 since H(0) is constant. That gives us the plaintext of one message — either the survival message or the death message.

2. Now we want to learn the other message m1, but we don't know k1 = (x0 - x1)^d mod n, and we can't compute it because we don’t have d.

3. So we open a second connection, get a new x0' and x1', and send v' = x0 - x1 + x0'

   then:

   ```
   k0' = (v' - x0')^d = (x0 - x1)^d = k1
   ```

   so the new connection gives us:

   ```
   c0' = m0' ⊕ H(k1)
   ```

4. If we can guess m0', we recover H(k1), and then use it to decrypt m1 from the main connection.

This works because the set of possible m0' values is small and predictable. Half the time, m0' is a death message, and there are only about 10 of them, all with a known format. So we brute-force through the list and if we find one that decrypts correctly, we’ve recovered H(k1) and therefore m1.

If not, we kill the second connection and try again.

This process is repeated for each of the 64 rounds. In each one, we chain the successful survival message (which contains the page number) and send it back to the main connection to keep moving forward.


## Solve script

```python
import hashlib
from pwn import *
from Crypto.Util.strxor import strxor

DEATH_CAUSES = [
    'a fever',
    'dysentery',
    'measles',
    'cholera',
    'typhoid',
    'exhaustion',
    'a snakebite',
    'a broken leg',
    'a broken arm',
    'drowning',
]

def encrypt(k, msg):
    key = k.to_bytes(128, 'big')
    msg = msg.encode().ljust(64, b'\x00')
    pad = hashlib.shake_256(key).digest(len(msg))
    return strxor(pad, msg)

def decrypt(k, msg):
    key = k.to_bytes(128, 'big')
    pad = hashlib.shake_256(key).digest(len(msg))
    return strxor(pad, msg)

def try_msg0(c0):
    msg0 = decrypt(0, c0)
    if b"you continue walking" in msg0:
        return int(msg0.decode().split(" ")[-1].split(".")[0])
    return None

def makeconn():
    return remote('dicec.tf', 31002)

def try_newconn(known, c1, n, max_attempts=10):
    for _ in range(max_attempts):
        conn2 = makeconn()
        conn2.recvuntil(b'Winxy Pistol Edition ===\n')
        conn2.recvline()

        conn2.recvuntil(b'the tunnel forks ahead. do you take the left or right path?\n')
        _n = int(conn2.recvline().decode().strip().split('n: ')[1])
        _e = int(conn2.recvline().decode().strip().split('e: ')[1])
        x0 = int(conn2.recvline().decode().strip().split('x0: ')[1])
        x1 = int(conn2.recvline().decode().strip().split('x1: ')[1])

        if _n != n:
            conn2.close()
            continue

        v2 = (known + x0) % n
        conn2.sendlineafter(b'v: ', str(v2).encode())
        c0p = bytes.fromhex(conn2.recvline().decode().split('c0: ')[1].strip())
        _ = conn2.recvline()

        conn2.close()

        xorval = strxor(c0p, c1)
        for cause in DEATH_CAUSES:
            death_msg = f'you die of {cause}.'.encode().ljust(64, b'\x00')
            guess = strxor(xorval, death_msg)
            if b"you continue walking" in guess:
                try:
                    return int(guess.decode().split(" ")[-1].split(".")[0])
                except:
                    continue
    return None

conn = makeconn()
conn.recvuntil(b'Winxy Pistol Edition ===\n')
conn.recvline()

for epoch in range(64):
    conn.recvuntil(b'the tunnel forks ahead. do you take the left or right path?\n')
    n = int(conn.recvline().decode().split('n: ')[1])
    e = int(conn.recvline().decode().split('e: ')[1])
    x0 = int(conn.recvline().decode().split('x0: ')[1])
    x1 = int(conn.recvline().decode().split('x1: ')[1])

    v = x0
    conn.sendlineafter(b'v: ', str(v).encode())

    c0 = bytes.fromhex(conn.recvline().decode().split('c0: ')[1].strip())
    c1 = bytes.fromhex(conn.recvline().decode().split('c1: ')[1].strip())

    page = try_msg0(c0)
    if page is None:
        known = (x0 - x1) % n
        page = try_newconn(known, c1, n)
        if page is None:
            log.error(f"[{epoch}] Failed to find live message.")
            conn.close()
            exit(1)

    conn.sendlineafter(b'turn to page: ', str(page).encode())

print(conn.recvall().decode())
```

## Flag
```
dice{lu5tr0us_j3wel_tr1nk3t}
```

Thank you to DiceGang for the fun challenges! Excited to play at finals this summer. 