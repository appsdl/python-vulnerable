# vuln_path_traversal.py
# Bandit should flag unsanitized file path usage
import sys
import os

BASE_DIR = "/tmp/data"  # assume this is the intended safe directory

def read_user_file(rel_path):
    # intentionally naive join allowing "../" attacks
    target = os.path.join(BASE_DIR, rel_path)
    with open(target, "r") as f:
        return f.read()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python vuln_path_traversal.py <relative-path>")
        sys.exit(1)
    print(read_user_file(sys.argv[1]))