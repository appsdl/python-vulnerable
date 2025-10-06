# vuln_tempfile.py
# Bandit flags insecure temporary file creation (B308)
import tempfile
import os

def write_report(data):
    # intentionally creating predictable temp file (delete=False)
    tmp = tempfile.NamedTemporaryFile(prefix="report_", delete=False)
    tmp.write(data.encode("utf-8"))
    tmp.close()
    print("Wrote report to:", tmp.name)
    return tmp.name

if __name__ == "__main__":
    fname = write_report("sensitive test content")
    # quickly demonstrate unsafe usage
    print("Contents:", open(fname).read())
    os.remove(fname)