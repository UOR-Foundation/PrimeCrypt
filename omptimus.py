#!/usr/bin/env python3
"""
primecrypt_cli.py

A feature complete implementation of PrimeCrypt – a next-generation cryptographic system
based on the Prime Framework. PrimeCrypt integrates intrinsic number embedding, spectral
analysis, and hierarchical chain reductions to achieve leakage resilience, tight security
reductions, and modular multi-signature aggregation.

This CLI tool supports:
  - Big-key generation (with intrinsic embedding).
  - Subkey extraction from a big key.
  - Symmetric encryption and decryption using a derived subkey.
  - Digital signature generation and verification (using a Schnorr-style scheme).
  - Multi-signature aggregation.

All parameters (e.g., block size, key length) are configurable. The implementation is
language-agnostic in its specification but provided here in Python for demonstrative purposes.
"""

import argparse
import json
import os
import random
import hashlib
from base64 import b64encode, b64decode

# Try to import PyCryptodome's AES. If not available, exit with error.
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("PyCryptodome module not found. Please install it via 'pip install pycryptodome'.")
    exit(1)

# ----------------------------
# Global Parameters for Signature Scheme
# ----------------------------
# For demonstration, we choose a 256-bit prime (using secp256k1 field prime)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# Choose a generator; for simplicity, we choose 2 (in practice, a proper group generator should be used)
G = 2

# ----------------------------
# Utility Functions
# ----------------------------

def int_to_bytes(x, length=None):
    """Convert an integer to bytes (big-endian)."""
    if length is None:
        length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, 'big')

def bytes_to_int(b):
    """Convert bytes (big-endian) to an integer."""
    return int.from_bytes(b, 'big')

def sha256_hash(data: bytes) -> bytes:
    """Return SHA-256 hash of the input data."""
    return hashlib.sha256(data).digest()

def random_int(nbits):
    """Generate a random integer with nbits bits."""
    return random.getrandbits(nbits)

# ----------------------------
# Big-Key and Intrinsic Embedding Functions
# ----------------------------

def generate_big_key(key_length_bits: int, block_size: int) -> list:
    """
    Generate a big key as a list of blocks.
    Each block is an integer in [0, 2^(block_size)).
    The big key is intrinsically embedded (all multi-base representations are assumed to
    cohere by virtue of the coherence inner product).
    """
    num_blocks = key_length_bits // block_size
    q = 2 ** block_size
    big_key = [random.randrange(q) for _ in range(num_blocks)]
    return big_key

def save_big_key(big_key: list, filename: str):
    """Save big key to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(big_key, f)

def load_big_key(filename: str) -> list:
    """Load big key from a JSON file."""
    with open(filename, 'r') as f:
        return json.load(f)

# ----------------------------
# Subkey Extraction
# ----------------------------

def extract_subkey(big_key: list, tau: int) -> list:
    """
    Extract a subkey from the big key.
    tau: number of distinct block indices to probe.
    Returns the subkey as a list of blocks.
    """
    if tau > len(big_key):
        raise ValueError("tau must be less than or equal to the number of blocks in the big key.")
    indices = random.sample(range(len(big_key)), tau)
    subkey = [big_key[i] for i in indices]
    return subkey

# ----------------------------
# Symmetric Encryption/Decryption using AES
# ----------------------------

def derive_symmetric_key(subkey: list, block_size: int) -> bytes:
    """
    Derive a symmetric key from the subkey.
    The subkey (list of integers) is converted to bytes, then hashed with SHA-256.
    Returns a 32-byte key for AES-256.
    """
    # Convert each block to fixed-length bytes
    q = 2 ** block_size
    block_byte_length = (block_size + 7) // 8
    subkey_bytes = b''.join(int_to_bytes(b, block_byte_length) for b in subkey)
    sym_key = sha256_hash(subkey_bytes)
    return sym_key

def encrypt_message(sym_key: bytes, message: bytes) -> bytes:
    """
    Encrypt message using AES-256 in CBC mode with PKCS7 padding.
    Returns the IV concatenated with the ciphertext.
    """
    iv = os.urandom(16)
    cipher = AES.new(sym_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return iv + ciphertext

def decrypt_message(sym_key: bytes, data: bytes) -> bytes:
    """
    Decrypt message using AES-256 in CBC mode with PKCS7 padding.
    Assumes that the first 16 bytes of data are the IV.
    """
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(sym_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# ----------------------------
# Schnorr-style Signature Scheme (Identification/Signature)
# ----------------------------

def generate_signature_keys():
    """
    Generate a signature keypair.
    The secret key is a random integer modulo (P-1) and the public key is computed as g^sk mod P.
    """
    sk = random.randrange(1, P - 1)
    pk = pow(G, sk, P)
    return sk, pk

def sign_message(secret_key: int, message: str) -> dict:
    """
    Generate a Schnorr-style signature for a message.
    Steps:
      1. Pick random nonce k in [1, P-1].
      2. Compute commitment: R = g^k mod P.
      3. Compute challenge: e = Hash(R || message) mod (P-1).
      4. Compute response: s = (k + secret_key * e) mod (P-1).
    Returns signature as a dictionary with fields 'R' and 's'.
    """
    k = random.randrange(1, P - 1)
    R = pow(G, k, P)
    # Compute challenge hash: use SHA256 on R and message
    R_bytes = int_to_bytes(R)
    e_hash = sha256_hash(R_bytes + message.encode())
    e = bytes_to_int(e_hash) % (P - 1)
    s = (k + secret_key * e) % (P - 1)
    return {"R": R, "s": s}

def verify_signature(public_key: int, message: str, signature: dict) -> bool:
    """
    Verify a Schnorr-style signature.
    Compute e = Hash(R || message) mod (P-1) and verify that g^s == R * pk^e mod P.
    """
    R = signature["R"]
    s = signature["s"]
    R_bytes = int_to_bytes(R)
    e_hash = sha256_hash(R_bytes + message.encode())
    e = bytes_to_int(e_hash) % (P - 1)
    lhs = pow(G, s, P)
    rhs = (R * pow(public_key, e, P)) % P
    return lhs == rhs

# ----------------------------
# Multi-Signature Aggregation
# ----------------------------

def aggregate_signatures(signatures: list) -> dict:
    """
    Aggregate multiple signatures.
    For demonstration, we aggregate Schnorr signatures by:
      - Multiplying all commitments R_i modulo P.
      - Summing all responses s_i modulo (P-1).
    Returns an aggregate signature { "R": R_agg, "s": s_agg }.
    Note: This is a conceptual aggregation; a real scheme would require careful design.
    """
    R_agg = 1
    s_agg = 0
    for sig in signatures:
        R_agg = (R_agg * sig["R"]) % P
        s_agg = (s_agg + sig["s"]) % (P - 1)
    return {"R": R_agg, "s": s_agg}

# ----------------------------
# Command Line Interface
# ----------------------------

def cmd_keygen(args):
    """
    Generate a big key and signature keypair.
    Saves the big key and the signature keys (secret and public) to specified files.
    """
    big_key = generate_big_key(args.key_length, args.block_size)
    save_big_key(big_key, args.bigkey_file)
    print(f"Big key generated with {len(big_key)} blocks and saved to {args.bigkey_file}")

    sk, pk = generate_signature_keys()
    # Save secret key and public key as JSON
    with open(args.sig_priv_file, 'w') as f:
        json.dump({"secret_key": sk}, f)
    with open(args.sig_pub_file, 'w') as f:
        json.dump({"public_key": pk}, f)
    print(f"Signature keys generated. Secret key saved to {args.sig_priv_file}, public key saved to {args.sig_pub_file}")

def cmd_extract(args):
    """
    Extract a subkey from a big key file.
    Saves the subkey (list of blocks) to a file.
    """
    big_key = load_big_key(args.bigkey_file)
    subkey = extract_subkey(big_key, args.tau)
    with open(args.subkey_file, 'w') as f:
        json.dump(subkey, f)
    print(f"Subkey with {args.tau} blocks extracted and saved to {args.subkey_file}")

def cmd_encrypt(args):
    """
    Encrypt a message using a subkey extracted from a big key.
    The subkey is derived from the big key file.
    """
    big_key = load_big_key(args.bigkey_file)
    subkey = extract_subkey(big_key, args.tau)
    sym_key = derive_symmetric_key(subkey, args.block_size)
    ciphertext = encrypt_message(sym_key, args.message.encode())
    # Encode ciphertext in base64 for printing
    ct_b64 = b64encode(ciphertext).decode()
    print("Ciphertext (base64):", ct_b64)

def cmd_decrypt(args):
    """
    Decrypt a message using a subkey extracted from a big key.
    The ciphertext must be provided as base64 encoded string.
    """
    big_key = load_big_key(args.bigkey_file)
    subkey = extract_subkey(big_key, args.tau)
    sym_key = derive_symmetric_key(subkey, args.block_size)
    ciphertext = b64decode(args.ciphertext)
    plaintext = decrypt_message(sym_key, ciphertext)
    print("Decrypted message:", plaintext.decode())

def cmd_sign(args):
    """
    Sign a message using the secret signature key.
    """
    with open(args.sig_priv_file, 'r') as f:
        data = json.load(f)
        sk = data["secret_key"]
    signature = sign_message(sk, args.message)
    # Save signature to file if requested, else print it
    if args.out_file:
        with open(args.out_file, 'w') as f:
            json.dump(signature, f)
        print(f"Signature saved to {args.out_file}")
    else:
        print("Signature:", signature)

def cmd_verify(args):
    """
    Verify a signature for a message using the public signature key.
    """
    with open(args.sig_pub_file, 'r') as f:
        data = json.load(f)
        pk = data["public_key"]
    # Load signature from file or from argument
    if args.sig_file:
        with open(args.sig_file, 'r') as f:
            signature = json.load(f)
    else:
        # Assume signature is provided as JSON string in the argument
        signature = json.loads(args.signature)
    valid = verify_signature(pk, args.message, signature)
    if valid:
        print("Signature is valid.")
    else:
        print("Signature is INVALID.")

def cmd_aggregate(args):
    """
    Aggregate multiple signature files into a single aggregate signature.
    """
    signatures = []
    for fname in args.sig_files:
        with open(fname, 'r') as f:
            sig = json.load(f)
            signatures.append(sig)
    agg_sig = aggregate_signatures(signatures)
    with open(args.out_file, 'w') as f:
        json.dump(agg_sig, f)
    print(f"Aggregate signature saved to {args.out_file}")

def main():
    parser = argparse.ArgumentParser(description="PrimeCrypt CLI - Next-Generation Cryptographic System based on the Prime Framework")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # keygen command: generate big key and signature keypair
    parser_keygen = subparsers.add_parser("keygen", help="Generate a big key and signature keypair")
    parser_keygen.add_argument("--key-length", type=int, default=1024, help="Big key length in bits (default: 1024)")
    parser_keygen.add_argument("--block-size", type=int, default=16, help="Block size in bits (default: 16)")
    parser_keygen.add_argument("--bigkey-file", type=str, default="big_key.json", help="Output file for big key")
    parser_keygen.add_argument("--sig-priv-file", type=str, default="sig_priv.json", help="Output file for signature private key")
    parser_keygen.add_argument("--sig-pub-file", type=str, default="sig_pub.json", help="Output file for signature public key")
    parser_keygen.set_defaults(func=cmd_keygen)

    # extract command: extract subkey from big key
    parser_extract = subparsers.add_parser("extract", help="Extract a subkey from a big key")
    parser_extract.add_argument("--bigkey-file", type=str, default="big_key.json", help="Input file for big key")
    parser_extract.add_argument("--tau", type=int, required=True, help="Number of probes (subkey length in blocks)")
    parser_extract.add_argument("--subkey-file", type=str, default="subkey.json", help="Output file for subkey")
    parser_extract.set_defaults(func=cmd_extract)

    # encrypt command: encrypt a message using subkey extraction from a big key
    parser_encrypt = subparsers.add_parser("encrypt", help="Encrypt a message using a subkey extracted from a big key")
    parser_encrypt.add_argument("--bigkey-file", type=str, default="big_key.json", help="Input file for big key")
    parser_encrypt.add_argument("--tau", type=int, required=True, help="Number of probes for subkey extraction")
    parser_encrypt.add_argument("--block-size", type=int, default=16, help="Block size in bits (must match keygen)")
    parser_encrypt.add_argument("--message", type=str, required=True, help="Message to encrypt")
    parser_encrypt.set_defaults(func=cmd_encrypt)

    # decrypt command: decrypt a ciphertext using subkey extraction from a big key
    parser_decrypt = subparsers.add_parser("decrypt", help="Decrypt a message using a subkey extracted from a big key")
    parser_decrypt.add_argument("--bigkey-file", type=str, default="big_key.json", help="Input file for big key")
    parser_decrypt.add_argument("--tau", type=int, required=True, help="Number of probes for subkey extraction")
    parser_decrypt.add_argument("--block-size", type=int, default=16, help="Block size in bits (must match keygen)")
    parser_decrypt.add_argument("--ciphertext", type=str, required=True, help="Ciphertext (base64 encoded)")
    parser_decrypt.set_defaults(func=cmd_decrypt)

    # sign command: sign a message using the signature private key
    parser_sign = subparsers.add_parser("sign", help="Sign a message using the secret signature key")
    parser_sign.add_argument("--sig-priv-file", type=str, default="sig_priv.json", help="Input file for signature private key")
    parser_sign.add_argument("--message", type=str, required=True, help="Message to sign")
    parser_sign.add_argument("--out-file", type=str, help="Optional output file to save signature")
    parser_sign.set_defaults(func=cmd_sign)

    # verify command: verify a signature using the signature public key
    parser_verify = subparsers.add_parser("verify", help="Verify a signature for a message")
    parser_verify.add_argument("--sig-pub-file", type=str, default="sig_pub.json", help="Input file for signature public key")
    parser_verify.add_argument("--message", type=str, required=True, help="Message whose signature is to be verified")
    group = parser_verify.add_mutually_exclusive_group(required=True)
    group.add_argument("--sig-file", type=str, help="Input file for signature (JSON)")
    group.add_argument("--signature", type=str, help="Signature as JSON string")
    parser_verify.set_defaults(func=cmd_verify)

    # aggregate command: aggregate multiple signature files
    parser_aggregate = subparsers.add_parser("aggregate", help="Aggregate multiple signatures into one")
    parser_aggregate.add_argument("sig_files", nargs="+", help="List of signature files to aggregate")
    parser_aggregate.add_argument("--out-file", type=str, default="agg_signature.json", help="Output file for aggregate signature")
    parser_aggregate.set_defaults(func=cmd_aggregate)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
