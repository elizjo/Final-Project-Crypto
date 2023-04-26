from Crypto.PublicKey import RSA
import sys

def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))

def save_keypair(keypair, privkeyfile):
    with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM'))

def gen_keypair(self):
    # keypair goes to server folder
    privkeyfile = "rsa_keypair.pem"
    # pubkey file in client folder 
    pubkeyfile = "rsa_pubkey.pem"

    # creates a new 2048 bit RSA key pair
    keypair = RSA.generate(2048)
    self.save_publickey(keypair.publickey(), pubkeyfile)
    self.save_keypair(keypair, privkeyfile)

def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)

def load_keypair(privkeyfile):
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)