# GoogleCTF 2025 – crypto/numerology

*Published: 2025-06-27*

This weekend, I played [Google CTF 2025](https://capturetheflag.withgoogle.com) with a few members of PBR | UCLA. I wanted to do a quick walkthrough of the cryptography challenge I solved, **numerology**. 

This challenge came with a compiled Python file `crypto_numerology.cpython-312.pycs`, a JSON package with plaintext/ciphertext pairs, and a hint: *"I gave you the key, is that enough?"*.

From `init.sh`, I saw the script runs with `--rounds 1` and `--message_size 64`. ChaCha with 1 round is basically broken, so I wanted to see what exactly they changed.

I ran the `.pyc` through [pylingual](https://pylingual.io) to decompile it. The structure looked like ChaCha, but simplified:

- The constants (normally `"expand 32-byte k"`) were replaced with all zeros  
- It only ran one quarter-round, `mix_bits(s, 0, 4, 8, 12)`  
- After that, it just added the original state back in  

This basically means only four words `0, 4, 8, 12` actually mix. Everything else is just `state[i] + state[i]` which for key words is literally `2 * key[i]`.

That means a big chunk of the keystream is trivial. Bytes 4–15 are straight from doubling key words, so they’re predictable. Only the first four bytes (word 0) really involve the counter.

---

## Known plaintext attack

We know the flag format starts with `CTF{`. If we XOR the first 4 bytes of ciphertext with that we get keystream word 0. Then I reversed the single quarter-round to recover the counter value.

```python
ks0 = int.from_bytes(bytes(x ^ y for x, y in zip(ct[:4], b"CTF{")), "little")
ctr = rotr32((rotr32(ks0, 12) - k[4]) & 0xffffffff, 16)
````

Once I had the counter, I could reconstruct the state:

* words 4–11: key
* word 12: counter
* everything else: zero

We get the full keystream by running the quarter-round once and adding the original state back in.


## Solve script

```python
import struct

rotl32 = lambda v,c: ((v<<c)&0xffffffff)|(v>>(32-c))
rotr32 = lambda v,c: ((v>>c)|(v<<(32-c)))&0xffffffff

k = struct.unpack("<8I", bytes.fromhex("000000005c5470020000000031f4727bf7d4923400000000e7bbb1c900000000"))
ct = bytes.fromhex("692f09e677335f6152655f67304e6e40141fa702e7e5b95b46756e63298d80a9bcbbd95465795f21ef0a")

print(ct[4:16].decode())  # trivial keystream bytes

ks0 = int.from_bytes(bytes(x ^ y for x, y in zip(ct[:4], b"CTF{")), "little")
ctr = rotr32((rotr32(ks0, 12) - k[4]) & 0xffffffff, 16)

s = [0] * 16
s[4:12] = k
s[12] = ctr
i = s.copy()

a, b, c, d = s[0], s[4], s[8], s[12]
a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 16)
c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 12)
a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 8)
c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 7)

for idx, val in zip((0, 4, 8, 12), (a, b, c, d)):
    s[idx] = val
s = [(x + y) & 0xffffffff for x, y in zip(s, i)]

ks = struct.pack("<16I", *s)
print(bytes(c ^ k for c, k in zip(ct, ks)).decode())
```

## Flag

```
CTF{w3_aRe_g0Nn@_ge7_MY_FuncKee_monkey_!!}
```