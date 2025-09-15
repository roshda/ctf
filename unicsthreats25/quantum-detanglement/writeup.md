# UniVsThreats CTF 2025 - crypto/Quantum Detanglement

*published: 2025-05-06*

This weekend, I briefly solved a couple cryptography challenges at UniVsThreats CTF 2025, organized by the West University of Timișoara in Romania, with cyberplanet. 
I wanted to go through my solution for this "Quantum Detanglement" challenge involving linear algebra. 

## Description

"Alice built her own quantum computer, with some misterious functionalities. It's been proven to have 0 noise. She can even see the qubits' states while they are entangled, without changing their quantic state! Don't ask how, not even we understand the physics behind it quite yet. Luckily for Bob, it seems that she is fond of standard Bell states and superdense coding. Can you help him figure it out?"

We are provided no source code, only access to the instance.

```
% nc 91.99.1.179 60004
Initial state =  Matrix([[0], [sqrt(2)/2], [-sqrt(2)/2], [0]])
Matrix([[-sqrt(2)/2], [0], [0], [sqrt(2)/2]])
Matrix([[-sqrt(2)/2], [0], [0], [sqrt(2)/2]])
Matrix([[-sqrt(2)/2], [0], [0], [-sqrt(2)/2]])
...
Matrix([[0], [sqrt(2)/2], [sqrt(2)/2], [0]])
Matrix([[sqrt(2)/2], [0], [0], [-sqrt(2)/2]])
Matrix([[0], [-sqrt(2)/2], [sqrt(2)/2], [0]])

```


A review of basic quantum concepts:

* Qubits can exist in superpositions like α|0⟩+β|1⟩.
* Entanglement links two qubits into states like |Φ⁺⟩=(|00⟩+|11⟩)/√2, so that measuring one influences the other.
* Superdense coding uses a shared entangled pair so that sending one qubit can transmit two classical bits, by applying specific Pauli operations (I, X, Y, Z) to Alice’s qubit before sending.

We were basically given Alice’s quantum computer because every time you connected, it printed a sequence of full 2‑qubit state vectors, including the initial entanglement, intermediate gates, and a final state. Importantly, we only get the amplitudes, no measurement result. We need to find the flag that Alice encoded across multiple runs with superdense coding.

## side channel

Superdense coding requires that only Alice’s qubit travels, and Bob’s qubit remains local. An eavesdropper seeing only one qubit cannot reconstruct two bits because that qubit alone is maximally mixed. But here, Alice sees the combined two‑qubit state without collapse, and I thought this was a side‑channel.

I connected a few times to look at amplitude vector in each trace. It always matched one of the four Bell basis states:

* Φ⁺ = (|00⟩+|11⟩)/√2
* Ψ⁺ = (|01⟩+|10⟩)/√2
* Φ⁻ = (|00⟩−|11⟩)/√2
* Ψ⁻ = (|01⟩−|10⟩)/√2

On paper, these respectively map to classical bits 00, 01, 10, and 11. I first parsed each final vector as two bits and convert to ASCII, but this didn't work. 

## Superdense coding properties

Superdense coding encodes changes in that Alice applies a Pauli operator that moves one Bell state to another. If Alice applies I, the state remains identical and X swaps between the Φ and Ψ families, Z flips the sign within the same family, Y (equivalent to XZ up to phase) swaps and flips. By looking at how one run’s Bell vector transforms into the next run’s starting Bell vector, I could infer the Pauli gate and then the two bits. So basically the approach is to compare consecutive states. 

strategy:

1. label each Bell state with a small number (0–3) based on which amplitudes are ±√2/2.
2. build a lookup of (previous_label, current_label) → Pauli operator → two bits
3. connect repeatedly to extract label sequences and decode every transition.
4. get enough bits until the ASCII flag pattern appears

## solve.py

```
from pwn import remote
import re
import sys

HOST = '91.99.1.179'
PORT = 60004

# regex to capture the four amplitudes in each printed Matrix line
state_re = re.compile(
    r"Matrix\(\[\[([^\]]+)\], \[([^\]]+)\], \[([^\]]+)\], \[([^\]]+)\]\]\)"
)

# map amplitude-sign tuples to Bell state IDs:
# ID 0: Φ⁺ family, ID 1: Φ⁻ family, ID 2: Ψ⁺ family, ID 3: Ψ⁻ family
BELL_LABELS = {
    ( 1, 0, 0,  1): 0,  # +Φ⁺
    (-1, 0, 0, -1): 0,  # −Φ⁺ (global phase)
    ( 1, 0, 0, -1): 1,  # +Φ⁻
    (-1, 0, 0,  1): 1,  # −Φ⁻
    ( 0, 1, 1,  0): 2,  # +Ψ⁺
    ( 0,-1,-1,  0): 2,  # −Ψ⁺
    ( 0, 1,-1,  0): 3,  # +Ψ⁻
    ( 0,-1, 1,  0): 3,  # −Ψ⁻
}

# transition table: (old_id, new_id) to two-bit string
PAULI_TABLE = {
    (0, 0): '00',  # I: no change within Φ⁺
    (0, 2): '01',  # X: Φ⁺ → Ψ⁺
    (0, 1): '10',  # Z: Φ⁺ → Φ⁻
    (0, 3): '11',  # Y: Φ⁺ → Ψ⁻
    (1, 1): '00',  # I on Φ⁻
    (1, 3): '01',  # X: Φ⁻ → Ψ⁻
    (1, 0): '10',  # Z: Φ⁻ → Φ⁺
    (1, 2): '11',  # Y: Φ⁻ → Ψ⁺
    (2, 2): '00',  # I on Ψ⁺
    (2, 0): '01',  # X: Ψ⁺ → Φ⁺
    (2, 3): '10',  # Z: Ψ⁺ → Ψ⁻
    (2, 1): '11',  # Y: Ψ⁺ → Φ⁻
    (3, 3): '00',  # I on Ψ⁻
    (3, 1): '01',  # X: Ψ⁻ → Φ⁻
    (3, 2): '10',  # Z: Ψ⁻ → Ψ⁺
    (3, 0): '11',  # Y: Ψ⁻ → Φ⁺
}


def sign(s):
    s = s.strip()
    if s == '0':
        return 0
    return -1 if s.startswith('-') else 1


def bell_id(a, b, c, d):
    key = (sign(a), sign(b), sign(c), sign(d))
    return BELL_LABELS[key]


def run_once():
    io = remote(HOST, PORT, timeout=5)
    labels = []

    try:
        while True:
            line = io.recvline()
            if not line:
                break
            decoded = state_re.search(line.decode())
            if decoded:
                # extract amplitude strings and map to a Bell ID
                labels.append(bell_id(*decoded.groups()))
    except EOFError:
        pass
    finally:
        io.close()

    return labels


def main():
    # number of connections (runs) to attempt, default 50
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    bits = ''
    prev_labels = None

    for i in range(runs):
        labels = run_once()
        if prev_labels is not None:
            # include the transition from the end of prev_labels to the start of labels
            sequence = prev_labels[-1:] + labels
            for old, new in zip(sequence, sequence[1:]):
                bits += PAULI_TABLE[(old, new)]

        prev_labels = labels

        # convert bits to ASCII text and search for the flag pattern
        if len(bits) >= 16:
            # only attempt when we have at least two bytes
            text = ''.join(
                chr(int(bits[j:j+8], 2))
                for j in range(0, len(bits) - len(bits) % 8, 8)
            )
            if 'UVT{' in text:
                print({text})
                return

    print("failed")

if __name__ == '__main__':
    main()
    

```


## flag

```
UVT{M4st3r_0f_m4trix_mu1tip1ic4ti0n}
```
