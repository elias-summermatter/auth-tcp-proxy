"""Generate a bcrypt hash for config.yaml.

Usage:
    python hash_password.py              # prompts for password
    python hash_password.py mypassword   # hashes the argument
"""
import getpass
import sys

import bcrypt


def main() -> None:
    if len(sys.argv) > 1:
        pw = sys.argv[1]
    else:
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Confirm: "):
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    print(bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode())


if __name__ == "__main__":
    main()
