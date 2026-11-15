# EECS 3481 - Task 5.4: Length-Extension Attack on SHA-256(K || M)
# R. Al Omari 
# Complete TODO 1, TODO 2 and TODO 3 in Part 3

import hashlib
import hmac
import os
import struct

# ------------------------------------------------------------
# Part 1: SHA-256 that can continue from a previous hash
#         (do not change)
# ------------------------------------------------------------
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


# SHA-256 compression function: process one 64-byte block
def compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + t1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xFFFFFFFF

    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, [a, b, c, d, e, f, g, h])]


# Padding SHA-256 adds to a message of `length` bytes:
# 0x80, then zero bytes, then the length in bits (8 bytes)
def sha256_padding(length):
    zeros = (55 - length) % 64
    return b"\x80" + b"\x00" * zeros + struct.pack(">Q", length * 8)


# Continue SHA-256 from an existing hash value.
# total_length = number of bytes hashed in total, including the earlier part.
def sha256_resume(old_hash, data, total_length):
    state = list(struct.unpack(">8I", old_hash))
    data = data + sha256_padding(total_length)
    for i in range(0, len(data), 64):
        state = compress(state, data[i:i+64])
    return b"".join(struct.pack(">I", x) for x in state)


# ------------------------------------------------------------
# Part 2: The server (do not change)
# ------------------------------------------------------------
secret_key = os.urandom(8)    # Eve does not know this


def server_tag(message):
    return hashlib.sha256(secret_key + message).digest()


def server_hmac(message):
    return hmac.new(secret_key, message, hashlib.sha256).digest()


# ------------------------------------------------------------
# Part 3: Eve's attack
# ------------------------------------------------------------
M = b"amount=100&to=alice"
tag = server_tag(M)           # Eve sees M and tag
ext = b"&to=eve"              # Eve wants to add this

print("Original message:", M)
print("Original tag:    ", tag.hex())
print()

for key_len in range(1, 33):    # Eve guesses the key length

    # TODO 1: Rebuild the padding SHA-256 added after K || M when the server
    #         computed the tag. It depends only on the length, not on the key.
    #         (i.e., call sha256_padding with key_len + len(M))
    glue = b""

    # TODO 2: Build the message Eve will send to the server.
    #         (i.e., the original message, then the glue padding, then ext)
    forged_msg = b""

    # TODO 3: Compute a valid tag for the forged message without the key, by
    #         continuing SHA-256 from where the server stopped.
    #         (i.e., call sha256_resume starting from tag, hashing ext, with a
    #         total length of key_len + len(forged_msg))
    forged_tag = b""

    if server_tag(forged_msg) == forged_tag:
        print("Key length", key_len, ": accepted")
        print()
        print("Forged message:", forged_msg)
        print("Forged tag:    ", forged_tag.hex())
        print("Glue padding:  ", glue.hex(), "(", len(glue), "bytes )")

        # Try the same idea on HMAC-SHA-256.
        # HMAC's outer SHA-256 hashes 64 bytes (padded key) + 32 bytes (inner hash),
        # plus 32 bytes of padding = 128 bytes. Eve can extend that outer hash, but
        # the server never hashes anything after the inner hash, so the forgery fails.
        print()
        hmac_tag = server_hmac(M)
        forged_hmac = sha256_resume(hmac_tag, ext, 128 + len(ext))
        if server_hmac(forged_msg) == forged_hmac:
            print("HMAC-SHA-256: forgery accepted")
        else:
            print("HMAC-SHA-256: forgery rejected")
        break
    else:
        print("Key length", key_len, ": rejected")
