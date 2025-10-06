# Bandit vs Secuarden test repo

This repo intentionally contains vulnerable sample Python files to exercise static analysis tools:
- Each file demonstrates a common category of insecure coding practice.
- Run Bandit locally: `bandit -r .`
- Run Secuarden scans (your usual pipeline) and compare results.

**DO NOT** run these on production or on internet-exposed systems. Use an isolated VM/container.