# pywarden

A simple open source password manager built in Python. This project is a work in progress.

## Installation

First:

```bash
pip install requirements.txt
```

For GUI:

```bash
python3 pywarden-gui.py
```

For CLI:

```bash
python3 pywarden-cli.py
```

## Pitfalls (as of now, tasks to be done)

1. Hashes your password but hashes are stored in plaintext. This is a security risk.
2. No password strength checker.
3. No password generator.
