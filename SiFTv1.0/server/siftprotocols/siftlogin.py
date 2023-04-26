#python3

import time
import secrets
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

class SiFT_LOGIN_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_LOGIN:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        # --------- STATE ------------
        self.mtp = mtp
        self.server_users = None 


    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users


    # builds a login request from a dictionary
    def build_login_req(self, login_req_struct):

        login_req_str = login_req_struct['timestamp'] + self.delimiter
        login_req_str += login_req_struct['username']
        login_req_str += self.delimiter + login_req_struct['password'] 
        login_req_str += self.delimiter + login_req_struct['client_random'] 
        return login_req_str.encode(self.coding)

    # parses a login request into a dictionary
    def parse_login_req(self, login_req):

        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        login_req_struct = {}
        
        # added timestamp
        login_req_struct['timestamp'] = login_req_fields[0]
        login_req_struct['username'] = login_req_fields[1]
        login_req_struct['password'] = login_req_fields[2]
        login_req_struct['client_random'] = login_req_fields[3]

        return login_req_struct


    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):
        login_res_str = login_res_struct['request_hash'].hex() 
        login_res_str += self.delimiter + login_res_struct['server_random']
        return login_res_str.encode(self.coding)


    # parses a login response into a dictionary
    def parse_login_res(self, login_res):
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {}
        
        login_res_struct['request_hash'] = bytes.fromhex(login_res_fields[0])
        login_res_struct['server_random'] =  bytes.fromhex(login_res_fields[1])
        return login_res_struct


    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):
        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        if pwdhash == usr_struct['pwdhash']: return True
        return False

    def prod_ftk(self, client_random, server_random, request_hash):
        # produces the final transfer key used in encrypting messages after handshake
        # symmetric key encryption, pass to mtp object
        key_material =  bytearray.fromhex(client_random + server_random)
        salt = request_hash
        # final transfer key is 32 bytes long, SHA256 as hash funct, salt
        final_key = HKDF(key_material, 32, salt, SHA256)
        return final_key

    
    # handles login process (to be used by the server)
    def handle_login_server(self):

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        # trying to receive a login request
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # processing login request
        hash_fn = SHA256.new() # create new SHA256 hash object
        hash_fn.update(msg_payload) # hash of the payload of login request
        request_hash = hash_fn.digest() # convert to byte string

        login_req_struct = self.parse_login_req(msg_payload)

        # checking timestamp
        current_time = time.time_ns()
        # window is (current_time - 1 sec, current_time + 1 sec)
        time_sent = int(login_req_struct['timestamp'])
        if (time_sent < (current_time - 1000000000 )) or (time_sent > (current_time + 1000000000)):
            raise SiFT_LOGIN_Error('Request is not within time window')
        
        # checking username and password
        if login_req_struct['username'] in self.server_users:
            if not self.check_password(login_req_struct['password'], self.server_users[login_req_struct['username']]):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unkown user attempted to log in')

        # building login response
        login_res_struct = {}
        login_res_struct['request_hash'] = request_hash
        login_res_struct['server_random'] = str(secrets.token_hex(16))
        msg_payload = self.build_login_res(login_res_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # sending login response
        try:
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('User ' + login_req_struct['username'] + ' logged in')
        # DEBUG 

        # if the send_msg was successful, connection is still present
        # client has already checked that the hash has not changed & is valid

        # we calculate the ftk for the server here
        client_rnd = login_req_struct['client_random']
        server_rnd = login_res_struct['server_random']
        final_transfer_key = self.prod_ftk(client_rnd, server_rnd, request_hash)
        
        # set final key here (will also discard temp_key)
        self.mtp.set_ftk(final_transfer_key)

        return login_req_struct['username']


    # handles login process (to be used by the client)
    def handle_login_client(self, username, password):

        # building a login request
        login_req_struct = {}

        # added timestamp
        login_req_struct['timestamp'] = str(time.time_ns())
        login_req_struct['username'] = username
        login_req_struct['password'] = password

         # added random generation of 16 byte hex
        login_req_struct['client_random'] = str(secrets.token_hex(16))
        msg_payload = self.build_login_req(login_req_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # trying to send login request
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # computing hash of sent request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # trying to receive a login response
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # processing login response
        login_res_struct = self.parse_login_res(msg_payload)

        # checking request_hash receiveid in the login response
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')
        
        else: 
            # we can calculate key here (bc hash was verified)
            client_rnd = login_req_struct['client_random']
            server_rnd = login_res_struct['server_random']
            final_transfer_key = self.prod_ftk(client_rnd, server_rnd, request_hash)
            
            # set final key here (will also reset temp key)
            self.mtp.set_ftk(final_transfer_key)

