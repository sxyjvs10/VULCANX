import glob
import subprocess
import os

target_pub = """-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBsB438YhfxJjqQdOPsa3jS
e0XKQX1G8kYRI0OFC6N5EBEDvX8QCUT4h3NFCtZ8roEIeraeft2gSm6YsT1rm8SN
cyeB9QNweWJniA6auKR7avG9jtSFk+62cCItzqQpZkD+3SysVGkqgt2/bZCfafuE
UPgdDjkSTDJc1hBnIXVOEcEuXYNVDtsZ5AcNGykP2lVumNRzURKJGXQO+IsTQjku
urIkL+pvd4wxJ6IS9NCFqKHQtxk06DNWZM49XinoLs+SuooPGOtdeRzrX0RcGhYS6
g1MJ4tYzY0rS6KRsTHw6usUGpiIDYOZj9Chu8pUvcd6UKSCSJ+2MX0oaG48yGZzZ
AgMBAAE=
-----END PUBLIC KEY-----"""

def get_modulus(key_content, is_public=False):
    with open("temp_key", "w") as f:
        f.write(key_content)
    cmd = ["openssl", "rsa", "-modulus", "-noout"]
    if is_public:
        cmd.append("-pubin")
    cmd.extend(["-in", "temp_key"])
    try:
        res = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
        return res.strip()
    except:
        return None
    finally:
        if os.path.exists("temp_key"):
            os.remove("temp_key")

target_mod = get_modulus(target_pub, True)
print(f"Target Modulus: {target_mod}")

for pem in glob.glob("private_key*.pem"):
    with open(pem, "r") as f:
        content = f.read()
    mod = get_modulus(content)
    if mod == target_mod:
        print(f"[+] MATCH FOUND: {pem}")
    else:
        print(f"[-] No match: {pem}")
