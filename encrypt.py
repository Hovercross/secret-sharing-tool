#!/usr/bin/env python

import argparse
from pathlib import Path
from base64 import b64encode
import json
from typing import List, Tuple

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.SecretSharing import Shamir


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "required",
        metavar="N",
        type=int,
        help="Number of keys required for decryption",
    )

    parser.add_argument(
        "original_file",
        help="The original file with your secret data",
    )

    args = parser.parse_args()

    required_count: int = args.required
    original_file = Path(args.original_file)

    if not original_file.is_file():
        raise ValueError("Input file must be a file")

    random_key = get_random_bytes(16)
    cipher = AES.new(random_key, AES.MODE_EAX)

    with open(original_file, "rb") as f_in:
        original_data = f_in.read()

    encrypted_data, tag = cipher.encrypt_and_digest(original_data)
    encoded_encrypted_data = b64encode(encrypted_data).decode("ascii")

    public_key_dir = Path("public_keys")
    public_key_files = list(public_key_dir.glob("*.public.json"))
    key_parts: List[Tuple[int, bytes]] = Shamir.split(
        required_count,
        len(public_key_files),
        random_key,
    )

    public_keys: List[Tuple[int, str]] = []

    public_key_dir = Path("public_keys")
    for file in public_key_dir.glob("*.public.json"):
        with open(file) as f_in:
            part_index, key_part_bytes = key_parts.pop()
            key_part = key_part_bytes

            public_key_data = json.load(f_in)
            public_key_str = "\n".join(public_key_data["key"])
            public_key = RSA.import_key(public_key_str)
            public_cipher = PKCS1_OAEP.new(public_key)
            public_share = public_cipher.encrypt(key_part)

            public_keys.append(
                {
                    "index": part_index,
                    "keyHolder": public_key_data["id"],
                    "share": public_share.hex(),
                }
            )

    base_name = original_file.name
    output_data = {
        "tag": tag.hex(),
        "nonce": cipher.nonce.hex(),
        "version": 1,
        "data": encoded_encrypted_data.splitlines(),
        "shares": sorted(public_keys, key=lambda k: k["index"]),
        "originalName": str(original_file),
    }

    output_name = f"{base_name}.secret.json"
    with open(output_name, "w") as f_out:
        json.dump(output_data, f_out, indent=2)


if __name__ == "__main__":
    main()
