# Squ1rrel CTF 2025 – crypto/secure vigenere

*Published: 2025-04-09*

This weekend, I played Vanderbilt University's Squ1rrel CTF with Psi Beta Rho.

This writeup will walk through my process of solving the simple cryptography challenge "Secure Vigenère."

On connection, the server gives you a Vigenère-encrypted flag using a random key composed of letters from `"squirrelctf"`:

```

Welcome! Here's the flag! It's just encrypted with a vigenere cipher with a random key!
The key is a random length, and I randomly picked letters from "squirrelctf" to encrypt the flag!
Flag: jkjlmyghsuwkefvtiuhzguznqgixwh

````

This is a Vigenère cipher where the plaintext flag is constant, but each ciphertext uses a random key. The random key is always 11 characters drawn from "squirrelctf", so each letter in the flag is shifted by one of just 11 possible values.

Since the encryption is just a Caesar shift per character, that means each position in the flag can only map to 11 possible ciphertext characters.  
This means that by collecting multiple ciphertexts, we can intersect the possible plaintexts per position using sets. 


## Solve script 

```python
from pwn import *
from collections import Counter

HOST = "20.84.72.194"
PORT = 5007
KEY_ALPHABET = "squirrelctf"
NUM_SAMPLES = 50

def get_ciphertext():
    with remote(HOST, PORT) as conn:
        conn.recvuntil(b"Flag: ")
        return conn.recvline().strip().decode()

def collect_ciphertexts(n):
    return [get_ciphertext() for _ in range(n)]

def recover_plaintext(ciphertexts):
    transposed = list(zip(*ciphertexts))
    plaintext = ''
    for chars in transposed:
        freq_counter = Counter()
        for c in chars:
            for k in KEY_ALPHABET:
                shift = ord(k) - ord('a')
                p = (ord(c) - ord('a') - shift) % 26
                freq_counter[chr(p + ord('a'))] += 1
        plaintext += freq_counter.most_common(1)[0][0]
    return plaintext

def main():
    ciphertexts = collect_ciphertexts(NUM_SAMPLES)
    plaintext = recover_plaintext(ciphertexts)
    print(f"squ1rrel{{{plaintext}}}")

if __name__ == "__main__":
    main()
````


## Flag

```
squ1rrel{ithoughtrandomizationwassecure}
