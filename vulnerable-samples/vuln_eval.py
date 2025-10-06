# vuln_eval.py
# Bandit should flag use of eval on untrusted input (B307)
import sys

def compute(expr):
    # intentionally unsafe: evaluating user-provided expression
    return eval(expr)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python vuln_eval.py '<expression>'")
        sys.exit(1)
    print("Result:", compute(sys.argv[1]))