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


for bits in [16, 20, 24]:
    print("Hash size:", bits, "bits")

    start = time.time()
    x1, x2, tries = find_collision(bits)
    print("  Collision:", tries, "tries (expected about", 2 ** (bits // 2), ")",
          round(time.time() - start, 2), "s")

    target = h(b"hello", bits)
    start = time.time()
    x, tries = find_preimage(bits, target)
    print("  Preimage: ", tries, "tries (expected about", 2 ** bits, ")",
          round(time.time() - start, 2), "s")

print()
print("32-bit collision:")
x1, x2, tries = find_collision(32)
print("  x1 =", x1.hex(), " h =", hex(h(x1, 32)))
print("  x2 =", x2.hex(), " h =", hex(h(x2, 32)))
print("  tries:", tries)
