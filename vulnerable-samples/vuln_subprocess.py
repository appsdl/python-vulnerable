# vuln_subprocess.py
# Bandit flags shell=True and unsanitized input (B602/B603)
import subprocess
import sys

def run_command(cmd):
    # intentionally dangerous: using shell=True with user input
    return subprocess.check_output(cmd, shell=True, text=True)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vuln_subprocess.py <command>")
        sys.exit(1)
    out = run_command(" ".join(sys.argv[1:]))
    print(out)