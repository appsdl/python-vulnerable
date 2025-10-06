# vuln_insecure_ssl.py
# Bandit flags insecure SSL/TLS usage (B506/B501)
import requests

def fetch_insecure(url):
    # intentionally disable TLS verification
    resp = requests.get(url, verify=False)
    return resp.status_code, resp.text[:200]

if __name__ == "__main__":
    status, snippet = fetch_insecure("https://example.com")
    print("Status:", status)
    print("Snippet:", snippet)