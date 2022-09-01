#!/usr/bin/env python

import json
from uuid import uuid4
import os
from pathlib import Path

from Crypto.PublicKey import RSA


def main():
    public_dir = Path("public_keys")
    private_dir = Path("private_keys")

    if not public_dir.exists():
        os.mkdir(public_dir)

    if not private_dir.exists():
        os.mkdir(private_dir)

    key_id = uuid4().hex

    private_key = RSA.generate(4096)
    private_key_lines = private_key.export_key("PEM").decode("ascii").splitlines()
    public_key = private_key.public_key()
    public_key_lines = public_key.export_key("PEM").decode("ascii").splitlines()

    private_data = {
        "id": key_id,
        "key": private_key_lines,
        "version": 1,
        "side": "private",
    }

    public_data = {
        "id": key_id,
        "key": public_key_lines,
        "version": 1,
        "side": "public",
    }

    private_file_name = f"{key_id}.private.json"
    private_file_path = private_dir / private_file_name

    public_file_name = f"{key_id}.public.json"
    public_file_path = public_dir / public_file_name

    with open(private_file_path, "w") as f_out:
        json.dump(private_data, f_out, indent=2)

    with open(public_file_path, "w") as f_out:
        json.dump(public_data, f_out, indent=2)


if __name__ == "__main__":
    main()
