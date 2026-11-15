# EECS 3481 - Task 5.3: Birthday Attack vs. Preimage Attack
# R. Al Omari
# Complete TODO 1 and TODO 2, then run: python3 birthday_vs_preimage_starter.py

import hashlib
import os
import time


# Return the first `bits` bits of SHA-256(x) as an integer
def h(x, bits):
    d = hashlib.sha256(x).digest()
    return int.from_bytes(d, "big") >> (256 - bits)


# Birthday attack: find any two inputs with the same hash
def find_collision(bits):
    seen = {}    # hash -> input
    tries = 0
    while True:
        x = os.urandom(16)
        tries += 1
        d = h(x, bits)

        # TODO 1: Check whether this hash has appeared before (whether another 
        #         input has already produced this hash). If it has, you
        #         found a collision (return the two distinct inputs and 
        #         the number of attempts); if not, remember it for later tries.
        #         (i.e., if d is already in seen, return seen[d], x and tries;
        #         otherwise, store x in seen under the key d)


# Preimage attack: find an input matching one fixed target hash
def find_preimage(bits, target):
    tries = 0
    while True:
        x = os.urandom(16)
        tries += 1

        # TODO 2: Check whether this input hits the one fixed target value.
        #         (i.e., if h(x, bits) equals target, return x and tries)


print("bits | collision tries  ~2^(m/2)    time | preimage tries       ~2^m    time")
for bits in [16, 20, 24]:
    start = time.time()
    x1, x2, ctries = find_collision(bits)
    ctime = time.time() - start

    target = h(b"hello", bits)
    start = time.time()
    x, ptries = find_preimage(bits, target)
    ptime = time.time() - start

    print(f"{bits:>4} | {ctries:>15,} {2 ** (bits // 2):>9,} {ctime:>6.2f}s |"
          f" {ptries:>14,} {2 ** bits:>10,} {ptime:>6.2f}s")

print()
print("32-bit collision found:")
x1, x2, tries = find_collision(32)
print(f"  x1 = {x1.hex()}   h = {h(x1, 32):08x}")
print(f"  x2 = {x2.hex()}   h = {h(x2, 32):08x}")
print(f"  tries: {tries:,}")
