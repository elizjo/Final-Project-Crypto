#python3

import socket
import rsa_keygen
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 0
		self.version_minor = 5
		self.msg_hdr_ver = b'\x01\x00'
		self.msg_hdr_rsv = b'\x00\x00'
		self.msg_hdr_sqn = b'\x00\x01'

		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2

		self.size_msg_hdr_mac = 28 # MAC length (12) + header length (16)
		self.size_login_tempkey = 256  # tempkey length (256)

		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.rcv_sqn = b'\x00\x01'
		self.peer_socket = peer_socket
		self.temp_key = None
		self.final_key = None


	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'] = msg_hdr[i:i+self.size_msg_hdr_rsv]
		return parsed_msg_hdr


	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)

		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')
		
		# for errors in sqn, failed mac varification => no error message
		if parsed_msg_hdr['sqn'] > self.rcv_sqn:
			raise SiFT_MTP_Error()

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			# we exclude the message header in enc_msg_body
			enc_msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
			cipher_nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd'] 

			# must save the temp_key for login response to encrypt its data
			if parsed_msg_hdr['typ'] == self.type_login_req:
				msg_body, self.temp_key = self.auth_decrypt_login_req(enc_msg_body, msg_hdr, cipher_nonce)
				# login messages are longer than any other normal type message (need to account for tempkey size)
				size_payload = msg_len - self.size_msg_hdr_mac - self.size_login_tempkey
			# use temporary key
			elif parsed_msg_hdr['typ'] == self.type_login_res:
				msg_body = self.auth_decrypt(enc_msg_body, msg_hdr, self.temp_key)
				size_payload = msg_len - self.size_msg_hdr_mac
			else: 
				msg_body = self.auth_decrypt(enc_msg_body, msg_hdr, self.final_key)
				size_payload = msg_len - self.size_msg_hdr_mac
				
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		# DEBUG 

		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ' )
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(msg_body) != size_payload: 
			raise SiFT_MTP_Error('Incomplete message body reveived')
		
		# incr the receiving sqn number
		rcv_sqn_int = int.from_bytes(self.rcv_sqn, "big") + 1
		self.rcv_sqn = rcv_sqn_int.to_bytes(2, 'big')


		return parsed_msg_hdr['typ'], msg_body


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	def auth_encrypt(self, msg_payload, msg_hdr, key):
		# returns the message (combined msg_header + encrypted payload + mac)
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		cipher_nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
		
		AES_GCM_cipher = AES.new(key, AES.MODE_GCM, nonce= cipher_nonce, mac_len = 12)

		# authenticate header w/o encryption 
		AES_GCM_cipher.update(msg_hdr)
		enc_payload, mac = AES_GCM_cipher.encrypt_and_digest(msg_payload)

		return enc_payload, mac
	
	def auth_decrypt_login_req(self, msg_body, msg_hdr, cipher_nonce):
		# used by server to decrypt the login request from the client
		# etk = msg_body[-256:]
		etk = msg_body[-self.size_login_tempkey:]
		mac = msg_body[-(self.size_login_tempkey + 12):-self.size_login_tempkey:]
		self.temp_key = self.dec_etk(etk)
		epd = msg_body[:-(self.size_login_tempkey + 12)]

		try: 
			AES_GCM_cipher = AES.new(self.temp_key, AES.MODE_GCM, nonce = cipher_nonce, mac_len = 12)
			# update used since msg_hdr is not encrypted but mac protected
			AES_GCM_cipher.update(msg_hdr)
			
			dec_payload = AES_GCM_cipher.decrypt_and_verify(epd, mac)

		except SiFT_MTP_Error as e:
			# maybe add msg to debug here
			raise SiFT_MTP_Error()
		
		return dec_payload, self.temp_key
	

	def auth_decrypt(self, enc_msg_body, msg_hdr, key):
		# decrypts any type of incoming message, can use the temp or final transfer key
		try: 
			parsed_msg_hdr = self.parse_msg_header(msg_hdr)

			cipher_nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']

			AES_GCM_cipher = AES.new(key, AES.MODE_GCM, nonce = cipher_nonce, mac_len = 12)
			
			AES_GCM_cipher.update(msg_hdr)
			# mac is length 12, so located in last 12 bytes
			mac = enc_msg_body[-12:]
			payload = enc_msg_body[:-12]

			dec_payload = AES_GCM_cipher.decrypt_and_verify(payload, mac)

		except SiFT_MTP_Error as e:
			# maybe add msg to debug here
			raise SiFT_MTP_Error()
		return dec_payload
	
	def enc_tk(self, temp_key):
		# allows client to encrypt temporary key
		# "srvpubkey.pem" for prof's key
		pubkey = rsa_keygen.load_publickey("rsa_pubkey.pem")
		RSAcipher = PKCS1_OAEP.new(pubkey)
		etk = RSAcipher.encrypt(temp_key) 
		return etk
 
	def dec_etk(self, enc_temp_key):
		# allows server to 
		# decrypt the encrypted temporary key recieved from client's login request
		keypair = rsa_keygen.load_keypair("rsa_keypair.pem")
		RSAcipher = PKCS1_OAEP.new(keypair)
		tk = RSAcipher.decrypt(enc_temp_key) 
		return tk
	
	def build_login_req(self, msg_hdr, msg_payload):
		# builds the login request message that returns encrypted message (w/o header), mac, and etk
		# compute tk
		self.temp_key = Random.get_random_bytes(32)
		etk = self.enc_tk(self.temp_key)

		# msg includes header, epd, and mac
		enc_msg, mac = self.auth_encrypt(msg_payload, msg_hdr, self.temp_key)

		# returns etk and msg
		return enc_msg, mac, etk
	
	def set_ftk(self, final_key):
		self.final_key = final_key
		# once we calculate final key, we dispose the temp key
		self.temp_key = None

	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		
		# build message
		# generate sqn and rnd
		msg_rnd = Random.get_random_bytes(6)

		
		if msg_type == self.type_login_req:
			# special case: login request (has different msg_size and uses temp_key)
			msg_size = self.size_msg_hdr_mac + len(msg_payload) + self.size_login_tempkey
			msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
			msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + self.msg_hdr_sqn + msg_rnd + self.msg_hdr_rsv

			# we will authen decrypt here, generate and use temp key
			enc_msg, mac, etk = self.build_login_req(msg_hdr, msg_payload)

			# create final msg by concatining header + encrypted msg + mac + encrypted key
			final_msg = msg_hdr + enc_msg + mac + etk

		# normal case (uses established key, msg_size is 28, msg_hdr + mac)
		else:
			msg_size = self.size_msg_hdr_mac + len(msg_payload)
			msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')

			# special case for keys: login response (key is etk from login request)
			if msg_type == self.type_login_res:
				key_used = self.temp_key
			# other case uses final transfer key
			else:
				key_used = self.final_key

			# msg_header
			msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + self.msg_hdr_sqn + msg_rnd + self.msg_hdr_rsv

			# use the final transfer key (ftk)
			enc_msg, mac = self.auth_encrypt(msg_payload, msg_hdr, key_used)

			final_msg = msg_hdr + enc_msg + mac
			

		# DEBUG 
		if self.DEBUG and (msg_type == self.type_login_req):
			print('MTP message to send (' + str(len(final_msg)) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(enc_msg)) + '): ' + enc_msg.hex())
			print('MAC (' + str(len(mac)) + '): ' + mac.hex())
			print('ETK (' + str(len(etk)) + '): ' + etk.hex())
			print('------------------------------------------')
		# DEBUG 
		elif self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(enc_msg)) + '): ' + enc_msg.hex())
			print('MAC (' + str(len(mac)) + '): ' + mac.hex())
			print('------------------------------------------')


		# try to send
		try:
			# final_msg includes header, payload, and mac tag
			self.send_bytes(final_msg)
			
			# incr sqn number
			msg_sqn_int = int.from_bytes(self.msg_hdr_sqn, "big") + 1
			self.msg_hdr_sqn = msg_sqn_int.to_bytes(2, 'big')

		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)


