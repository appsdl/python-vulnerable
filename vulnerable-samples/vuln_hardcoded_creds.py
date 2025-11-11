# vuln_hardcoded_creds.py
# Bandit flags hardcoded passwords / tokens (B105)
API_TOKEN = "super-secret-token-12345"  # intentionally hardcoded

def get_data():
    # pretend use of token
    print("Using token:", API_TOKEN[:8] + "..." )

if __name__ == "__main__":
    get_data()