from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_pub(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
        return serialization.load_pem_public_key(data, default_backend())
    except Exception as e:
        print(f"Error loading {path}: {e}")
        return None

def load_priv(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
            # replace literal \n with actual newlines if any
            data = data.replace(b"\\n", b"\n")
        return serialization.load_pem_private_key(data, password=None, backend=default_backend())
    except Exception as e:
        print(f"Error loading {path}: {e}")
        return None

target_pub = load_pub("target_pub.pem")
if target_pub:
    target_mod = target_pub.public_numbers().n
    print(f"Target modulus length: {target_pub.key_size}")
else:
    target_mod = None

import glob
for file in glob.glob("*.pem"):
    if "target" in file or "public" in file: continue
    priv = load_priv(file)
    if priv:
        if priv.private_numbers().public_numbers.n == target_mod:
            print(f"MATCH FOUND: {file}")
        else:
            print(f"No match: {file}")

