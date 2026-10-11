# gcm.py - AES-GCM encrypt/decrypt
# Usage: python3 gcm.py -e|-d KEY_HEX NONCE_HEX INFILE OUTFILE
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

op, key, nonce, infile, outfile = sys.argv[1:6]
gcm = AESGCM(bytes.fromhex(key))
data = open(infile, "rb").read()
if op == "-e":
    out = gcm.encrypt(bytes.fromhex(nonce), data, None)  # ciphertext + 16-byte tag
else:
    try:
        out = gcm.decrypt(bytes.fromhex(nonce), data, None)
    except InvalidTag:
        sys.exit("Decryption failed: authentication tag does not match. No output written.")
open(outfile, "wb").write(out)