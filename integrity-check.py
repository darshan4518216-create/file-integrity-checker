#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

HASH_FILE = ".integrity_hashes.json"


def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for block in iter(lambda: file.read(65536), b""):
            sha256.update(block)

    return sha256.hexdigest()


def get_files(path):
    path = Path(path)

    if path.is_file():
        return [path]

    if path.is_dir():
        return sorted(
            file for file in path.rglob("*")
            if file.is_file() and file.name != HASH_FILE
        )

    raise FileNotFoundError(f"Path not found: {path}")


def load_hashes():
    if not os.path.exists(HASH_FILE):
        return {}

    with open(HASH_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def save_hashes(hashes):
    temp_file = HASH_FILE + ".tmp"

    with open(temp_file, "w", encoding="utf-8") as file:
        json.dump(hashes, file, indent=4, sort_keys=True)

    os.replace(temp_file, HASH_FILE)


def init_integrity(path):
    hashes = {}

    for file in get_files(path):
        file_hash = calculate_hash(file)
        hashes[str(file)] = file_hash
        print(f"Hashing: {file}")

    save_hashes(hashes)

    print("\n✓ Hashes stored successfully.")


def check_integrity(path):
    stored_hashes = load_hashes()

    if not stored_hashes:
        print("Error: No stored hashes found.")
        print("Run 'init' first.")
        return

    current_files = get_files(path)
    current_paths = {str(file) for file in current_files}

    tampered = False

    for file in current_files:
        file_path = str(file)
        current_hash = calculate_hash(file)

        if file_path not in stored_hashes:
            print(f"{file}: NEW FILE")
            tampered = True

        elif current_hash != stored_hashes[file_path]:
            print(f"{file}: MODIFIED (Hash mismatch)")
            tampered = True

        else:
            print(f"{file}: Unmodified")

    for stored_file in stored_hashes:
        if stored_file not in current_paths:
            print(f"{stored_file}: DELETED")
            tampered = True

    if tampered:
        print("\n⚠ Integrity violation detected!")
    else:
        print("\n✓ All files are intact.")


def update_integrity(path):
    stored_hashes = load_hashes()

    if not stored_hashes:
        print("Error: No stored hashes found.")
        print("Run 'init' first.")
        return

    files = get_files(path)

    for file in files:
        stored_hashes[str(file)] = calculate_hash(file)
        print(f"Updated: {file}")

    save_hashes(stored_hashes)

    print("\n✓ Hashes updated successfully.")


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Checker using SHA-256"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="Initialize and store file hashes"
    )
    init_parser.add_argument("path")

    check_parser = subparsers.add_parser(
        "check",
        help="Check file integrity"
    )
    check_parser.add_argument("path")

    update_parser = subparsers.add_parser(
        "update",
        help="Update stored hashes"
    )
    update_parser.add_argument("path")

    args = parser.parse_args()

    try:
        if args.command == "init":
            init_integrity(args.path)

        elif args.command == "check":
            check_integrity(args.path)

        elif args.command == "update":
            update_integrity(args.path)

    except PermissionError:
        print("Error: Permission denied.")
        sys.exit(1)

    except Exception as error:
        print(f"Error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
