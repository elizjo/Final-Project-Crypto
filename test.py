#python3

import secrets

# these are two ways to generate 16 byte random number for key generation
print(secrets.token_hex(16))
print(str(hex(secrets.randbits(128)))[2:])