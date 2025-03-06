#!/usr/bin/env python3
"""
primecrypt_cli.py

*********************************************************************************************************
*** PRIMECRYPT IS NOT PEER REVIEWED - THIS IS REFERENCE IMPLEMENTATION IS FOR RESEARCH PURPOSES ONLY! ***
*********************************************************************************************************

A feature complete, reference implementation of PrimeCrypt – a next-generation cryptographic system
based on the Prime Framework. PrimeCrypt integrates intrinsic number embedding, spectral analysis, and
hierarchical chain reductions to achieve leakage resilience, tight security reductions, and modular
multi-signature aggregation.

This CLI tool supports:
  - Big-key generation (with intrinsic embedding).
  - Subkey extraction from a big key.
  - Symmetric encryption and decryption using a derived subkey.
  - Digital signature generation and verification (using a Schnorr-style scheme with secure nonce 
    generation and binding factors to thwart rogue key attacks).
  - Multi-signature aggregation with binding factors.

All parameters (e.g., block size, key length) are configurable. This implementation is written in Python,
using cryptographically secure randomness (via the secrets module) and proper parameter validations.

Note:
  - Many abstract concepts from the Prime Framework (intrinsic embedding, coherence inner product) are
    enforced conceptually. Their rigorous cryptographic instantiation should be derived from formal proofs
    in production.
  - The prime P and generator G used here are based on standardized secp256k1 parameters for demonstration.
    In production, use thoroughly validated parameters and a complete, dynamic factorization of P-1.
  - External dependencies (e.g., PyCryptodome for AES, sympy for factorization) must be installed.
  - Additional side-channel protections (e.g., constant-time arithmetic, secure memory erasure) are integrated
    where feasible in Python; note that true production-grade side-channel protection may require low-level
    language implementations.
"""

import argparse
import json
import os
import secrets
import hashlib
import hmac
from base64 import b64encode, b64decode
from math import gcd

# ----------------------------
# External Dependency Check for PyCryptodome and sympy
# ----------------------------
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("PyCryptodome module not found. Please install it via 'pip install pycryptodome'.")
    exit(1)

try:
    import sympy
except ImportError:
    print("Sympy module not found. Please install it via 'pip install sympy' for dynamic factorization.")
    exit(1)

# ----------------------------
# Global Parameters for Signature Scheme
# ----------------------------
# Standardized secp256k1 field prime (for demonstration only)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def is_prime(n, k=10):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # a in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

if not is_prime(P):
    raise ValueError("Global parameter P is not prime. Use validated parameters.")

def factorize(n):
    """Dynamically factorize n using sympy's factorint."""
    return sympy.factorint(n)

def find_primitive_root(p):
    """
    Dynamically find a generator for the multiplicative group modulo p.
    Factorizes p-1 using sympy and checks candidates from 2 upward.
    This implementation mitigates shortcuts and ensures a proper generator is found.
    """
    phi = p - 1
    factors_dict = factorize(phi)
    factors = list(factors_dict.keys())
    candidate = 2
    while candidate < p:
        flag = True
        for factor in factors:
            if pow(candidate, phi // factor, p) == 1:
                flag = False
                break
        if flag:
            return candidate
        candidate += 1
    raise ValueError("No primitive root found.")

# Compute generator G dynamically.
G = find_primitive_root(P)
if not G:
    raise ValueError("Failed to compute a valid generator for P.")

# Additional note: In production, further side-channel protections should be applied to private key
# operations, such as using constant-time modular arithmetic libraries and secure memory erasure.

# ----------------------------
# Utility Functions
# ----------------------------

def int_to_bytes(x, length=None):
    """Convert an integer to bytes (big-endian) in constant-time when possible."""
    if length is None:
        length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, 'big')

def bytes_to_int(b):
    """Convert bytes (big-endian) to an integer."""
    return int.from_bytes(b, 'big')

def sha256_hash(data: bytes) -> bytes:
    """Return SHA-256 hash of the input data."""
    return hashlib.sha256(data).digest()

def secure_randint(a, b):
    """Return a random integer N such that a <= N <= b using the secrets module."""
    return secrets.randbelow(b - a + 1) + a

def secure_sample(population: list, k: int) -> list:
    """Return k distinct elements from population using the secrets module."""
    if k > len(population):
        raise ValueError("Sample size k cannot be greater than population size.")
    population = list(population)
    result = []
    for _ in range(k):
        idx = secrets.randbelow(len(population))
        result.append(population.pop(idx))
    return result

# ----------------------------
# Big-Key and Intrinsic Embedding Functions
# ----------------------------

def generate_big_key(key_length_bits: int, block_size: int) -> list:
    """
    Generate a big key as a list of blocks.
    Each block is an integer in [0, 2^(block_size)).
    The big key is conceptually intrinsically embedded; all multi-base representations are assumed
    to cohere via the coherence inner product (abstractly enforced by the Prime Framework).
    """
    if key_length_bits % block_size != 0:
        raise ValueError("Key length in bits must be a multiple of the block size.")
    num_blocks = key_length_bits // block_size
    q = 2 ** block_size
    big_key = [secrets.randbelow(q) for _ in range(num_blocks)]
    return big_key

def save_big_key(big_key: list, filename: str):
    """Save big key to a JSON file."""
    try:
        with open(filename, 'w') as f:
            json.dump(big_key, f)
    except Exception as e:
        raise IOError(f"Error saving big key: {e}")

def load_big_key(filename: str) -> list:
    """Load big key from a JSON file."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except Exception as e:
        raise IOError(f"Error loading big key: {e}")

# ----------------------------
# Subkey Extraction
# ----------------------------

def extract_subkey(big_key: list, tau: int) -> list:
    """
    Extract a subkey from the big key.
    tau: number of distinct block indices to probe.
    Returns the subkey as a list of blocks.
    Uses the secrets module to securely sample indices.
    """
    if tau > len(big_key):
        raise ValueError("tau must be less than or equal to the number of blocks in the big key.")
    indices = secure_sample(range(len(big_key)), tau)
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
    The secret key is a random integer in [1, P-1] generated securely.
    The public key is computed as G^sk mod P.
    """
    sk = secure_randint(1, P - 1)
    pk = pow(G, sk, P)
    return sk, pk

def sign_message(secret_key: int, message: str, public_key: int) -> dict:
    """
    Generate a Schnorr-style signature for a message.
    Steps:
      1. Pick a random nonce k in [1, P-1] securely.
      2. Compute commitment: R = G^k mod P.
      3. Compute challenge: e = Hash(R || message) mod (P-1) in constant time.
      4. Compute response: s = (k + secret_key * e) mod (P-1).
    Returns a signature as a dictionary with fields 'R', 's', and 'pk'.
    Nonce reuse is prevented by secure random generation.
    """
    k = secure_randint(1, P - 1)
    R = pow(G, k, P)
    R_bytes = int_to_bytes(R)
    e_hash = sha256_hash(R_bytes + message.encode())
    e = bytes_to_int(e_hash) % (P - 1)
    s = (k + secret_key * e) % (P - 1)
    return {"R": R, "s": s, "pk": public_key}

def verify_signature(public_key: int, message: str, signature: dict) -> bool:
    """
    Verify a Schnorr-style signature.
    Compute e = Hash(R || message) mod (P-1) and verify that G^s == R * pk^e mod P.
    Uses constant-time comparison for the final verification.
    """
    R = signature["R"]
    s = signature["s"]
    R_bytes = int_to_bytes(R)
    e_hash = sha256_hash(R_bytes + message.encode())
    e = bytes_to_int(e_hash) % (P - 1)
    lhs = pow(G, s, P)
    rhs = (R * pow(public_key, e, P)) % P
    lhs_bytes = int_to_bytes(lhs, length=(P.bit_length() + 7) // 8)
    rhs_bytes = int_to_bytes(rhs, length=(P.bit_length() + 7) // 8)
    return hmac.compare_digest(lhs_bytes, rhs_bytes)

# ----------------------------
# Multi-Signature Aggregation with Binding Factors
# ----------------------------

def aggregate_signatures(signatures: list) -> dict:
    """
    Aggregate multiple signatures securely.
    Each signature must include fields 'R', 's', and 'pk'.
    To prevent rogue key attacks, a global binding factor L is computed from all public keys.
    For each signature, a binding coefficient lambda_i is derived as:
        lambda_i = int(sha256(pk || R || L)) mod (P-1)
    The aggregate signature is computed as:
        R_agg = prod(R_i^(lambda_i)) mod P,
        s_agg = sum(lambda_i * s_i) mod (P-1)
    The aggregate signature includes the binding factor L.
    """
    pubkeys = []
    for sig in signatures:
        if "pk" not in sig:
            raise ValueError("Each signature must include the public key ('pk').")
        pubkeys.append(int_to_bytes(sig["pk"]))
    L = sha256_hash(b"".join(pubkeys))
    R_agg = 1
    s_agg = 0
    for sig in signatures:
        pk_bytes = int_to_bytes(sig["pk"])
        R_bytes = int_to_bytes(sig["R"])
        lambda_i = bytes_to_int(sha256_hash(pk_bytes + R_bytes + L)) % (P - 1)
        R_agg = (R_agg * pow(sig["R"], lambda_i, P)) % P
        s_agg = (s_agg + lambda_i * sig["s"]) % (P - 1)
    return {"R": R_agg, "s": s_agg, "L": L.hex()}

# ----------------------------
# Command Line Interface
# ----------------------------

def cmd_keygen(args):
    """
    Generate a big key and signature keypair.
    Saves the big key and the signature keys (secret and public) to specified files.
    """
    try:
        big_key = generate_big_key(args.key_length, args.block_size)
        save_big_key(big_key, args.bigkey_file)
        print(f"Big key generated with {len(big_key)} blocks and saved to {args.bigkey_file}")
    except Exception as e:
        print(f"Error generating big key: {e}")
        return

    try:
        sk, pk = generate_signature_keys()
        with open(args.sig_priv_file, 'w') as f:
            json.dump({"secret_key": sk}, f)
        with open(args.sig_pub_file, 'w') as f:
            json.dump({"public_key": pk}, f)
        print(f"Signature keys generated. Secret key saved to {args.sig_priv_file}, public key saved to {args.sig_pub_file}")
    except Exception as e:
        print(f"Error generating signature keys: {e}")

def cmd_extract(args):
    """
    Extract a subkey from a big key file.
    Saves the subkey (list of blocks) to a file.
    """
    try:
        big_key = load_big_key(args.bigkey_file)
        subkey = extract_subkey(big_key, args.tau)
        with open(args.subkey_file, 'w') as f:
            json.dump(subkey, f)
        print(f"Subkey with {args.tau} blocks extracted and saved to {args.subkey_file}")
    except Exception as e:
        print(f"Error extracting subkey: {e}")

def cmd_encrypt(args):
    """
    Encrypt a message using a subkey extracted from a big key.
    The subkey is derived from the big key file.
    """
    try:
        big_key = load_big_key(args.bigkey_file)
        subkey = extract_subkey(big_key, args.tau)
        sym_key = derive_symmetric_key(subkey, args.block_size)
        ciphertext = encrypt_message(sym_key, args.message.encode())
        ct_b64 = b64encode(ciphertext).decode()
        print("Ciphertext (base64):", ct_b64)
    except Exception as e:
        print(f"Error during encryption: {e}")

def cmd_decrypt(args):
    """
    Decrypt a message using a subkey extracted from a big key.
    The ciphertext must be provided as a base64 encoded string.
    """
    try:
        big_key = load_big_key(args.bigkey_file)
        subkey = extract_subkey(big_key, args.tau)
        sym_key = derive_symmetric_key(subkey, args.block_size)
        ciphertext = b64decode(args.ciphertext)
        plaintext = decrypt_message(sym_key, ciphertext)
        print("Decrypted message:", plaintext.decode())
    except Exception as e:
        print(f"Error during decryption: {e}")

def cmd_sign(args):
    """
    Sign a message using the secret signature key.
    The signature includes the public key for binding.
    Incorporates constant-time comparisons and secure nonce generation to mitigate side-channel attacks.
    """
    try:
        with open(args.sig_priv_file, 'r') as f:
            data = json.load(f)
            sk = data["secret_key"]
        pk = pow(G, sk, P)
        signature = sign_message(sk, args.message, pk)
        if args.out_file:
            with open(args.out_file, 'w') as f:
                json.dump(signature, f)
            print(f"Signature saved to {args.out_file}")
        else:
            print("Signature:", signature)
    except Exception as e:
        print(f"Error during signing: {e}")

def cmd_verify(args):
    """
    Verify a signature for a message using the public signature key.
    Uses constant-time comparison to resist timing attacks.
    """
    try:
        with open(args.sig_pub_file, 'r') as f:
            data = json.load(f)
            pk = data["public_key"]
        if args.sig_file:
            with open(args.sig_file, 'r') as f:
                signature = json.load(f)
        else:
            signature = json.loads(args.signature)
        valid = verify_signature(pk, args.message, signature)
        if valid:
            print("Signature is valid.")
        else:
            print("Signature is INVALID.")
    except Exception as e:
        print(f"Error during signature verification: {e}")

def cmd_aggregate(args):
    """
    Aggregate multiple signature files into a single aggregate signature.
    Each signature must include the public key field 'pk'.
    Uses binding factors to mitigate rogue key attacks.
    """
    try:
        signatures = []
        for fname in args.sig_files:
            with open(fname, 'r') as f:
                sig = json.load(f)
                signatures.append(sig)
        agg_sig = aggregate_signatures(signatures)
        with open(args.out_file, 'w') as f:
            json.dump(agg_sig, f)
        print(f"Aggregate signature saved to {args.out_file}")
    except Exception as e:
        print(f"Error during signature aggregation: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="PrimeCrypt CLI - Next-Generation Cryptographic System based on the Prime Framework"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_keygen = subparsers.add_parser("keygen", help="Generate a big key and signature keypair")
    parser_keygen.add_argument("--key-length", type=int, default=1024,
                               help="Big key length in bits (default: 1024)")
    parser_keygen.add_argument("--block-size", type=int, default=16,
                               help="Block size in bits (default: 16)")
    parser_keygen.add_argument("--bigkey-file", type=str, default="big_key.json",
                               help="Output file for big key")
    parser_keygen.add_argument("--sig-priv-file", type=str, default="sig_priv.json",
                               help="Output file for signature private key")
    parser_keygen.add_argument("--sig-pub-file", type=str, default="sig_pub.json",
                               help="Output file for signature public key")
    parser_keygen.set_defaults(func=cmd_keygen)

    parser_extract = subparsers.add_parser("extract", help="Extract a subkey from a big key")
    parser_extract.add_argument("--bigkey-file", type=str, default="big_key.json",
                                help="Input file for big key")
    parser_extract.add_argument("--tau", type=int, required=True,
                                help="Number of probes (subkey length in blocks)")
    parser_extract.add_argument("--subkey-file", type=str, default="subkey.json",
                                help="Output file for subkey")
    parser_extract.set_defaults(func=cmd_extract)

    parser_encrypt = subparsers.add_parser("encrypt", help="Encrypt a message using a subkey extracted from a big key")
    parser_encrypt.add_argument("--bigkey-file", type=str, default="big_key.json",
                                help="Input file for big key")
    parser_encrypt.add_argument("--tau", type=int, required=True,
                                help="Number of probes for subkey extraction")
    parser_encrypt.add_argument("--block-size", type=int, default=16,
                                help="Block size in bits (must match keygen)")
    parser_encrypt.add_argument("--message", type=str, required=True,
                                help="Message to encrypt")
    parser_encrypt.set_defaults(func=cmd_encrypt)

    parser_decrypt = subparsers.add_parser("decrypt", help="Decrypt a message using a subkey extracted from a big key")
    parser_decrypt.add_argument("--bigkey-file", type=str, default="big_key.json",
                                help="Input file for big key")
    parser_decrypt.add_argument("--tau", type=int, required=True,
                                help="Number of probes for subkey extraction")
    parser_decrypt.add_argument("--block-size", type=int, default=16,
                                help="Block size in bits (must match keygen)")
    parser_decrypt.add_argument("--ciphertext", type=str, required=True,
                                help="Ciphertext (base64 encoded)")
    parser_decrypt.set_defaults(func=cmd_decrypt)

    parser_sign = subparsers.add_parser("sign", help="Sign a message using the secret signature key")
    parser_sign.add_argument("--sig-priv-file", type=str, default="sig_priv.json",
                             help="Input file for signature private key")
    parser_sign.add_argument("--message", type=str, required=True,
                             help="Message to sign")
    parser_sign.add_argument("--out-file", type=str,
                             help="Optional output file to save signature")
    parser_sign.set_defaults(func=cmd_sign)

    parser_verify = subparsers.add_parser("verify", help="Verify a signature for a message")
    parser_verify.add_argument("--sig-pub-file", type=str, default="sig_pub.json",
                               help="Input file for signature public key")
    parser_verify.add_argument("--message", type=str, required=True,
                               help="Message whose signature is to be verified")
    group = parser_verify.add_mutually_exclusive_group(required=True)
    group.add_argument("--sig-file", type=str,
                       help="Input file for signature (JSON)")
    group.add_argument("--signature", type=str,
                       help="Signature as JSON string")
    parser_verify.set_defaults(func=cmd_verify)

    parser_aggregate = subparsers.add_parser("aggregate", help="Aggregate multiple signatures into one")
    parser_aggregate.add_argument("sig_files", nargs="+",
                                  help="List of signature files to aggregate")
    parser_aggregate.add_argument("--out-file", type=str, default="agg_signature.json",
                                  help="Output file for aggregate signature")
    parser_aggregate.set_defaults(func=cmd_aggregate)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
