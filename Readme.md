# Split secret key utility

This is a secret utility for a demo. *It has in no way been vetted cryptographically, do not use it for anything important*

Utilities

- generate-key.py: Generate a new public/private key pair
- encrypt.py: Encrypt a file, taking the count of the number of individual keys that need to come together
- decrypt.py: Decript a file, taking the secret json file. At least the minimum number of required keys must be in the private_keys directory.