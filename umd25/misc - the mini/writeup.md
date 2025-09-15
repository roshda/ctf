# UMDCTF 2025 - misc/the-mini

*Published: 2025-05-06*

This weekend, I played UMDCTF 2025 with Psi Beta Rho at UCLA. I wanted to walk through my solution for one of the misc challenges, nyt/the-mini. 

## Context

In NYT Games, the Mini is a smaller version of the New York Times Crossword puzzle. NYT used to offer a .puz file download of the challenge each day, but they discontinued this in 2021. 
This file format isn't very well documented but I was able to read [Google Code archive’s PUZ File Format wiki](https://code.google.com/archive/p/puz/wikis/FileFormat.wiki) which was really useful. It described the header layout and how to detect a scrambled puzzle. 
I learned that .puz files use checksums and sometimes obfuscate their contents using a scrambling algorithm which we would need to reverse. 


According to the documentation:
>
> * Offset 0x1E: scrambled checksum
> * Offset 0x32: scrambled Ta
> * Offset 0x2C and 0x2D: width/height of the grid

I wrote a quick script to read these fields from the file.  

```python
import struct

data = open('the_mini.puz', 'rb').read()

# helper to read 2-byte little-endian integers
def read_u16(offset):
    return struct.unpack_from('<H', data, offset)[0]

# get header values
scrambled_tag = read_u16(0x32)
scrambled_cksum = read_u16(0x1E)
width = data[0x2C]
height = data[0x2D]

```
and got 

```
scramble tag: 4
scrambled checksum: 0x6A7F
dimensions: 5 x 5
```
meaning the puzzle is scrambled and we need to match a checksum to validate our solution. 

We eventually need to extract the scrambled solution string. According to documentation the .puz format stores the solution as a linear string starting at offset `0x34`. It’s one byte per cell (25 bytes here), and black squares are denoted with a period `.`.

> I used the grid dimensions to slice exactly 25 bytes from the file and decode them:

```python
solution_offset = 0x34
enc_grid = data[solution_offset : solution_offset + width * height].decode('latin-1')
print({enc_grid})
```
This gives us the raw scrambled data that we’ll feed into the unscrambler. Let’s figure out how that works next.

### Learning the Unscrambling Algorithm

According to the file format docs, scrambled puzzles go through a reversible sequence of transformations. The algorithm:

1. Caesar shift the letters using the full 4-digit key
2. Rotate left by the current digit of the key
3. Shuffle the string (interleave two halves)

To reverse that process, we need to apply those steps in reverse order and backwards through the key digits.

To comply with checksum verification later, we need to convert the board to column-major order (top-to-bottom, left-to-right), remove black squares before unscrambling, and then restore them afterward. 

```python
import string

BLACK = '.'
A2Z = string.ascii_uppercase

# turn a 4-digit number into a list of digits
def key_digits(key):
    return [int(c) for c in f"{key:04d}"]

# convert row-major board into column-major string
def square(txt, w, h):
    return ''.join(txt[r*w + c] for c in range(w) for r in range(h))

# replace each non-black square with a char from seq
def restore(mask, seq):
    it = iter(seq)
    return ''.join(next(it) if c != BLACK else BLACK for c in mask)

# reverse of the riffle shuffle (interleave)
def unshuffle(s):
    return s[1::2] + s[0::2]

# caesar shift by digit list (wraps every 4)
def shift(s, key_list):
    return ''.join(
        A2Z[(A2Z.index(c) + key_list[i % 4]) % 26] if c in A2Z else c
        for i, c in enumerate(s))

# main unscrambling
def unscramble(enc, w, h, key):
    # transpose
    col = square(enc, w, h)
    # remove black squares
    core = col.replace(BLACK, '')
    # apply 4 reverse rounds
    for digit in reversed(key_digits(key)):
        core = unshuffle(core)
        core = core[-digit:] + core[:-digit]      
        core = shift(core, [-d for d in key_digits(key)]) 
    # restore blacks and convert back to row-major
    full = restore(col, core)
    return ''.join(full[c*h + r] for r in range(h) for c in range(w))
```

With this we can unscramble with any 4 digit key, but we need to find the key the challenge used and we can brute force it. The only way to know we had correctly unscrambled the puzzle was to recompute its checksum and compare it to the 0x6A7F scrambled checksum from the header.


We know that the checksum is computed over the column-major version of the board with black squares removed thanks to the PUZ file format documentation, specifically the section about the Scrambled Checksum at offset 0x1E which says
"If the correct solution is laid out as a string in column-major order, omitting black squares, then 0x1E contains cksum_region (string,0x0000)."

Let's implement this:

```python
def cksum_region(data_bytes):
    c = 0
    for b in data_bytes:
        low = c & 1
        c >>= 1
        if low:
            c |= 0x8000
        c = (c + b) & 0xFFFF
    return c
```
Now to get the key, let's write a loop that will use this to try every key from 0000 to 9999, unscramble the grid, strip black squares and re-encode to bytes, cmpute the checksum and compare. 

```python
target_cksum = scrambled_cksum  # 0x6A7F from earlier

for key in range(10000):
    plain = unscramble(enc_grid, width, height, key)
    col_maj = square(plain, width, height).replace(BLACK, '').encode('latin-1')
    if cksum_region(col_maj) == target_cksum:
        print(f"{key:04d}")
        break
```
This gave us

```
5727
```
which we can use to restore the board. 

```python
solution = unscramble(enc_grid, width, height, 5727)
for row in range(height):
    print(' '.join(solution[row*width : (row+1)*width]))
```

resulting board:

```
U M D C T
F C A N Y
O U B E A
T M Y T I
M E . . .
```

## flag

```
UMDCTF{CANYOUBEATMYTIME}
```
 

Shoutout to the UMDCSEC team for putting together some great challenges with a really cohesive "brainrot" theme! This was a really interesting NYT puzzle themed category and I really enjoyed the cryptography and OSINT "ohio" challenges as well. 