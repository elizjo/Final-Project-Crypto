# Final-Project-Crypto

IMPORTANT: you only need to modify login.py, mtp.py, server.py and client.py for this purpose!

## Login Protocol (modifying siftlogin.py)

### Login Request
+ added time-stamp on login request tracking when client generated login request
+ added client_random (a 16-byte fresh random value using a cryptographic random number generator)
    + used python's [secrets](https://docs.python.org/3/library/secrets.html) module
    + used to allow client and server to contribute & generate final transfer key
+ added server_random (a 16-byte fresh random value using a cryptographic random number generator)

In 

+ generate an RSA key-pair for the server to encrypt the temporary key. 
    + put the key-pair file in the server folder 
    + the public key file in the client folder

In mtp file
+ expanded header from ver, typ, len (6 bytes) -> ver, typ, len, sqn, rnd, rsv (16 bytes)
added the following to recieve_msg:
    + verify sqn number if its larger than last recieved sqn number(prevent replay attacks)
    + verify mac

+ (via AES in GCM mode) encrypted the payload of the login request and produced an authentication tag


## Command Protocol

## Upload Protocol

## Download Protocol

