# vuln_md5_passwords.py
# Bandit should flag use of weak cryptography (B303/B324)
import hashlib

def store_password(username, password):
    # intentionally weak hashing (MD5, no salt)
    digest = hashlib.md5(password.encode("utf-8")).hexdigest()
    # pretend store (insecure)
    with open("pw_store.txt", "a") as f:
        f.write(f"{username}:{digest}\n")

if __name__ == "__main__":
    # example usage
    store_password("alice", "password123")
    print("Stored insecure MD5 hash for alice (for testing only).")