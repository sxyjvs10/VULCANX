from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import glob
import re

def load_pub_data(data):
    try:
        return serialization.load_pem_public_key(data.encode(), default_backend())
    except Exception as e:
        return None

def load_priv_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
            # replace literal \n with actual newlines
            data = data.replace(b"\\n", b"\n")
            # clean up any extra fluff
            if b"-----BEGIN" in data:
                data = data[data.find(b"-----BEGIN"):]
            if b"-----END" in data:
                data = data[:data.find(b"-----END")+len(b"-----END RSA PRIVATE KEY-----")+2]
        return serialization.load_pem_private_key(data, password=None, backend=default_backend())
    except Exception as e:
        # print(f"Error loading {path}: {e}")
        return None

pub1_pem = """-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBsB438YhfxJjqQdOPsa3jS
e0XKQX1G8kYRI0OFC6N5EBEDvX8QCUT4h3NFCtZ8roEIeraeft2gSm6YsT1rm8SN
cyeB9QNweWJniA6auKR7avG9jtSFk+62cCItzqQpZkD+3SysVGkqgt2/bZCfafuE
UPgdDjkSTDJc1hBnIXVOEcEuXYNVDtsZ5AcNGykP2lVumNRzURKJGXQO+IsTQjku
urIkL+pvd4wxJ6IS9NCFqKHQtxk06DNWZM49XinoLs+SuooPGOtdeRzrX0RcGhYS6
g1MJ4tYzY0rS6KRsTHw6usUGpiIDYOZj9Chu8pUvcd6UKSCSJ+2MX0oaG48yGZzZ
AgMBAAE=
-----END PUBLIC KEY-----"""

pub2_pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoL5u4dVAH4ZEhiVCy0j2
7A9cqNnpmOqnLGGxS3mKdCHTbSXg1fSSQwxu/2tKTN9JGH0TYj1P10Gg7pGPRJHK
HXNiiyJ2GxLCucv6yvAi7vwt3uh2xLuZoxlGA//qSCaeEcTpJvaW16EXc90dV366
ARRdxW5XHhDd9jpXrZNuyqSUcEcYD4iZURC+HseBrrtP7FocON2ChXfZFtED1fTk
cXr3paqrlmJPxIcx8fx/BNLdfk6fdfrbkt+6Ke6arwGDupdnSGfSSFfSLAH9h2bL
jeGlnSdhViDYQkdA3tJx3IBquiuNsI15Dc1HyXV6/N/zLEJt9wFiw9ME5WdVrB81
CQIDAQAB
-----END PUBLIC KEY-----"""

pub1 = load_pub_data(pub1_pem)
pub2 = load_pub_data(pub2_pem)

mod1 = pub1.public_numbers().n if pub1 else None
mod2 = pub2.public_numbers().n if pub2 else None

print(f"Target 1 Modulus: {hex(mod1)[:20]}..." if mod1 else "Target 1 Load Failed")
print(f"Target 2 Modulus: {hex(mod2)[:20]}..." if mod2 else "Target 2 Load Failed")

for file in glob.glob("*.pem") + glob.glob("*.txt"):
    priv = load_priv_file(file)
    if priv:
        m = priv.private_numbers().public_numbers.n
        if m == mod1:
            print(f"[!] MATCH FOUND with Target 1: {file}")
        elif m == mod2:
            print(f"[!] MATCH FOUND with Target 2: {file}")
        else:
            # print(f"[-] No match: {file}")
            pass

