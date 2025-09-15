# b01lers CTF 2025 - crypto/cve1
*published: 2025-04-22*

This weekend, I played b01lers CTF 2025 with Psi Beta Rho at UCLA (we won first place🎉). Here are a couple cryptography challenges I was able to solve.

## cve1: “Can’t prove to me that there’s a new vulnerability!”

Before attempting, I had to learn about the tools involved here. The challenge used a zero-knowledge proof system called zk-SNARKs, specifically the **Groth16** proving scheme, written in Circom, which lets you define verifiable circuits. 
These circuits are compiled and used to generate proofs over a finite field (in this case, the scalar field of the BN128 elliptic curve). The verifier checks whether a submitted proof matches the expected circuit logic using modular arithmetic under that field. 

We are provided self-contained zk-SNARK playground on a server:

```
https://cver1.harkonnen.b01lersc.tf/
```
We were given these files for the server. 

```
cverecord/
├── app.js                      
├── server.js                   
├── cverecord.circom           
├── cverecord.r1cs              
├── cverecord.zkey           
├── cverecord_verification_key.json
├── cverecord_js/
│   ├── generate_witness.js
│   ├── cverecord.wasm
│   ├── witness_calculator.js
│   └── cverecord_input.json    
```

This setup allows you to generate proofs locally to submit to the server. 

The circuit in cverecord.circom enforces these constraints:

- year ≤ 2025
- id ≤ 20035
- name[0..3] == 'DOGE' (ASCII check on the name)

The verification server in app.js does this:

```
if (await snarkjs.groth16.verify(vKey, publicSignals, proof)) {
    if (parseInt(publicSignals[1]) <= 2025) {
        res.end("The most recent CVEs were published in 2025!");
    } else {
        res.end("Wait, is your CVE from the future?\n" + flag);
    }
}
```

The verifier accepts proofs using snarkjs, but then adds a server-side check, parseInt(publicSignals[1]) < = 2025. 

## Exploit idea

My teammate Ronak found [this unresolved issue in the snarkjs repo](https://github.com/iden3/snarkjs/issues/423) which pointed to a vulnerability in the Solidity Groth16 verifier template:

```
mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))
```

khovratovich noticed that any out-of-range public input is reduced modulo q before verification. This keeps values in the scalar field but the server still sees the original input.

Then, from the provided cverecord verification key, I noticed that the field in this challenge was the scalar field of the elliptic curve BN128. I googled to find the modulus q of this field and found it in [this ethereum package](https://github.com/ethereum/py_ecc/blob/main/py_ecc/bn128/bn128_curve.py) that implements elliptic curve cryptography in Python. 

Given this, I then realized realized the key to breaking this is just setting q - 1. By the vulnerability, any two numbers that differ by a multiple of q represent the same field element to the zk‑SNARK verifier, so
(q – 1) mod q = q – 1, and (q – 1) ≡ –1 (mod q). Since the circuit only ever reasons about values mod q, we can bypass. 

Then when the server does 
'parseInt(publicSignals[1]) < = 2025' it’s looking at the raw decimal string “2188824…5616” and correctly concludes it’s far larger than 2025 so we get the “future CVE” branch.

## Implementation


Solving this involved changing just one number in the source.
The challenge provides you with all the tools you need to generate witnesses and proofs. 

1. Replace the "year" in cverecord_input.json with q - 1.

``` 
{
  "year": "21888242871839275222246405745257275088548364400416034343698204186575808495616",
  "id": "20035",
  "name": ["68","79","71","69","32","68","101","110","105","97","108","32","111","102","32","83","11","114","118","105","99","101","0","0","0","0","0","0","0","0","0","0"]
}
```

2: Generate witness and proof with these two commands.

```bash
node cverecord_js/generate_witness.js \
  cverecord_js/cverecord.wasm \
  cverecord_input.json \
  witness.wtns

npx snarkjs groth16 prove \
  cverecord.zkey \
  witness.wtns \
  proof.json \
  public.json
```

3: Submit the proof to the server.

```bash
curl -s -X POST https://cver1.harkonnen.b01lersc.tf/ \
  -H "Content-Type: application/json" \
  -d "$(jq -n --argfile proof proof.json --argfile input public.json '{proof: $proof, input: $input}')"
```


## flag

```txt
bctf{d0n1_f0r93t_t0_54n1t1z3_1nput5_6y_3n4c3n9_c1rcu1t_c0n5tr8nts}
```

Ronak is the goat for finding this GitHub issue. 


Thank you to the b01lers CTF team for putting together some great challenges for us to enjoy this weekend! 
