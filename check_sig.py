#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse

def check_command(command):
    """Check if a command is available in the system PATH."""
    try:
        subprocess.run(['which', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def check_apk_signature(file_path):
    print(f"[*] Analyzing Android Application (APK): {file_path}")
    
    # Prefer apksigner as it verifies v1, v2, v3, and v4 signatures
    if check_command("apksigner"):
        print("[+] 'apksigner' found. Verifying signature...")
        cmd = ["apksigner", "verify", "--verbose", "--print-certs", file_path]
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            print(result.stdout)
            if result.returncode == 0:
                print("\033[92m[+] APK Signature Verification SUCCESSFUL.\033[0m")
            else:
                print("\033[91m[-] APK Signature Verification FAILED.\033[0m")
        except Exception as e:
            print(f"[-] Error running apksigner: {e}")
    
    # Fallback to keytool (only verifies JAR/v1 signatures and extracts cert info)
    elif check_command("keytool"):
        print("[-] 'apksigner' not found. Falling back to 'keytool' (Note: Only checks v1/JAR signatures).")
        cmd = ["keytool", "-printcert", "-jarfile", file_path]
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            print(result.stdout)
            if "Not a signed jar file" in result.stdout:
                print("\033[91m[-] APK is NOT signed (or missing v1 signature).\033[0m")
            elif result.returncode == 0:
                print("\033[92m[+] APK Signature (v1) Extracted SUCCESSFULLY.\033[0m")
            else:
                print("\033[91m[-] APK Signature Verification FAILED.\033[0m")
        except Exception as e:
            print(f"[-] Error running keytool: {e}")
    else:
        print("[-] Error: Neither 'apksigner' nor 'keytool' are installed.")
        print("    Install apksigner: sudo apt-get install apksigner")
        print("    Install keytool: sudo apt-get install default-jdk")

def check_exe_signature(file_path):
    print(f"[*] Analyzing Windows Executable (EXE): {file_path}")
    
    # Use osslsigncode to verify Authenticode signatures
    if check_command("osslsigncode"):
        print("[+] 'osslsigncode' found. Verifying Authenticode signature...")
        cmd = ["osslsigncode", "verify", file_path]
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            print(result.stdout)
            if result.returncode == 0:
                print("\033[92m[+] EXE Signature Verification SUCCESSFUL.\033[0m")
            else:
                print("\033[91m[-] EXE Signature Verification FAILED.\033[0m")
        except Exception as e:
            print(f"[-] Error running osslsigncode: {e}")
            
    # Fallback to checking via Python LIEF if installed (less common, but possible in environments)
    else:
        print("[-] Error: 'osslsigncode' is not installed.")
        print("    Install osslsigncode: sudo apt-get install osslsigncode")
        print("\n[*] Attempting fallback using python 'lief' module...")
        try:
            import lief
            binary = lief.parse(file_path)
            if not binary:
                print("[-] Could not parse PE file.")
                return

            if binary.has_signatures:
                print("\033[92m[+] EXE has Authenticode signatures.\033[0m")
                for i, sig in enumerate(binary.signatures):
                    print(f"\nSignature {i + 1}:")
                    print(f"  Digest Algorithm: {sig.digest_algorithm}")
                    print(f"  Signer(s):")
                    for signer in sig.signers:
                        print(f"    - Serial Number: {signer.serial_number.hex()}")
                        print(f"    - Issuer: {signer.issuer}")
                print("\033[93m[*] Note: LIEF extracts signature info but does not perform full cryptographic verification against root CA by default in this script.\033[0m")
            else:
                print("\033[91m[-] EXE is NOT signed.\033[0m")

        except ImportError:
            print("[-] Python 'lief' module is not installed either. Cannot analyze EXE signature.")
            print("    Run 'sudo apt install osslsigncode' for best results.")

def main():
    parser = argparse.ArgumentParser(description="Check digital signatures of Android (APK) and Windows (EXE) applications.")
    parser.add_argument("file", help="Path to the .apk or .exe file")
    
    args = parser.parse_args()
    file_path = args.file
    
    if not os.path.isfile(file_path):
        print(f"[-] Error: File '{file_path}' does not exist.")
        sys.exit(1)
        
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext == ".apk":
        check_apk_signature(file_path)
    elif ext in [".exe", ".dll", ".sys"]:
        check_exe_signature(file_path)
    else:
        print(f"[-] Unsupported file extension: {ext}")
        print("[*] Please provide an .apk or .exe file.")
        sys.exit(1)

if __name__ == "__main__":
    main()
