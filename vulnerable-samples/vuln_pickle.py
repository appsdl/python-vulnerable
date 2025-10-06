# vuln_pickle.py
# Bandit should flag use of pickle for untrusted data (B301-style)
import pickle
import sys

def load_user_blob(path):
    with open(path, "rb") as f:
        # intentionally unsafe: untrusted pickle load
        obj = pickle.load(f)
    return obj

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python vuln_pickle.py <pickle-file>")
        sys.exit(1)
    data = load_user_blob(sys.argv[1])
    print("Loaded object:", type(data), data)