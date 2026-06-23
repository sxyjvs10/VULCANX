#!/usr/bin/env python3
import subprocess
import sys
import argparse
import time

def check_ip():
    print("[*] Checking current Tor IP...")
    try:
        # -q makes proxychains quiet to only show the command output
        result = subprocess.run(
            ['proxychains4', '-q', 'curl', '-s', 'https://checkip.amazonaws.com'], 
            capture_output=True, text=True, timeout=15
        )
        ip = result.stdout.strip()
        if ip:
            print(f"[+] Current Tor IP: {ip}\n")
        else:
            print("[-] Failed to fetch IP. Is Tor running?\n")
    except Exception as e:
        print(f"[-] Error checking IP: {e}\n")

def restart_tor():
    print("[*] Requesting new Tor identity (restarting Tor)...")
    result = subprocess.run(['systemctl', 'restart', 'tor@default'])
    if result.returncode == 0:
        print("[+] Tor restarted successfully. Waiting for circuits to build...")
        time.sleep(3)
    else:
        print("[-] Failed to restart Tor. You might need sudo privileges.")

def run_command(cmd):
    print(f"[*] Running via proxychains: {' '.join(cmd)}")
    print("-" * 40)
    try:
        # Use -q to suppress proxychains internal logs so the output is cleaner
        subprocess.run(['proxychains4', '-q'] + cmd)
    except KeyboardInterrupt:
        print("\n[*] Execution cancelled by user.")
    except Exception as e:
        print(f"[-] Error executing command: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="A simple wrapper for proxychains4 to easily run commands and manage Tor IPs.",
        usage="%(prog)s [options] [command ...]",
        epilog="Examples:\n  %(prog)s curl http://ifconfig.me\n  %(prog)s -r nmap -sT -Pn -p 80 example.com\n  %(prog)s -i"
    )
    parser.add_argument('-i', '--ip', action='store_true', help="Show the current Tor IP address and exit")
    parser.add_argument('-r', '--renew', action='store_true', help="Restart Tor to get a new IP before running the command")
    parser.add_argument('command', nargs=argparse.REMAINDER, help=argparse.SUPPRESS)

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    if args.renew:
        restart_tor()
        # If no command is provided, just show the new IP
        if not args.command:
            check_ip()

    elif args.ip:
        check_ip()

    if args.command:
        cmd = args.command
        # Handle potential '--' separator from argparse
        if cmd and cmd[0] == '--':
            cmd = cmd[1:]
        
        if cmd:
            # Check IP implicitly if we just renewed it
            if args.renew:
               check_ip()
            run_command(cmd)

if __name__ == '__main__':
    main()
