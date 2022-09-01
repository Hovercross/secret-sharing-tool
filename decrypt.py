#!/usr/bin/env python

import argparse
from pathlib import Path
from base64 import b64decode, b64encode
import json
from typing import Any, Dict, List, Tuple

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.SecretSharing import Shamir


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "secret_file",
        help="The file with the secret encoded data",
    )

    args = parser.parse_args()

    secret_file = Path(args.secret_file)

    if not secret_file.is_file():
        raise ValueError("Input file must be a file")

    secret_keys = {}
    private_key_dir = Path("private_keys")
    for private_file in private_key_dir.glob("*.private.json"):
        with open(private_file) as f_in:
            private_data = json.load(f_in)

        id = private_data["id"]
        if private_data["side"] != "private":
            continue

        rsa_key = RSA.import_key("\n".join(private_data["key"]))
        secret_keys[id] = rsa_key

    with open(secret_file) as f_in:
        encoded_data = json.load(f_in)

    # Read all the keys that were encrypted
    available_keys = []
    for share in encoded_data["shares"]:
        keyholder: str = share["keyHolder"]
        encrypted_key_part: bytes = bytes.fromhex(share["share"])
        index: int = share["index"]

        if keyholder in secret_keys:
            rsa_key = secret_keys[keyholder]
            key_cipher = PKCS1_OAEP.new(rsa_key)
            key_part = key_cipher.decrypt(encrypted_key_part)

            available_keys.append((index, key_part))

    # Get back the AES key that was used to encrypt this file
    key = Shamir.combine(available_keys)

    nonce = bytes.fromhex(encoded_data["nonce"])
    tag = bytes.fromhex(encoded_data["tag"])
    original_name = encoded_data["originalName"]

    aes_cipher = AES.new(key, AES.MODE_EAX, nonce)
    encrypted_data = b64decode("\n".join(encoded_data["data"]))
    plain_text_data = aes_cipher.decrypt(encrypted_data)
    aes_cipher.verify(tag)

    with open(f"decoded/{original_name}", "wb") as f_out:
        f_out.write(plain_text_data)


if __name__ == "__main__":
    main()
