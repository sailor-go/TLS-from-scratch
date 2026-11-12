
import handshake
import ccs 
import record
import keys 
import socket
import struct

CIPHER_SUITE_STR_AES128_SHA = "AES128-SHA"
CIPHER_SUITE_STR_NULL_SHA = "NULL-SHA"

CIPHER_SUITE_AES_SHA = b"\x00\x2f"
CIPHER_SUITE_NULL_SHA= b"\x00\x02"

CIPHER_LIST = { CIPHER_SUITE_STR_AES128_SHA:CIPHER_SUITE_AES_SHA, CIPHER_SUITE_STR_NULL_SHA:CIPHER_SUITE_NULL_SHA }

class DemoTLS12(socket.socket):
	def __init__(self,cipher_suite):
		self.cipher_suite = cipher_suite
		if cipher_suite == CIPHER_SUITE_STR_AES128_SHA:
			self.cipher_algr = keys.CIPHER_AES128
			self.hmac_algr = keys.HMAC_SHA
		elif cipher_suite == CIPHER_SUITE_STR_NULL_SHA:
			self.cipher_algr = keys.CIPHER_NULL
			self.hmac_algr = keys.HMAC_SHA
		else:
			raise Exception

		super(DemoTLS12,self).__init__()

	def send_clienthellos(self):
		clnt_hello, clnt_random, clnt_version = handshake.constuct_clnthello(CIPHER_LIST[self.cipher_suite])
		self.clnt_random = clnt_random
		self.clnt_version =clnt_version
		self.hsk_messages = clnt_hello  # rfc 5246 7.4.9  for generating client finished message
		clnt_hello_record = record.wrap_record(clnt_hello,record.RECORD_TYPE_HSK)
		self.send(clnt_hello_record)
		return 

	def send_clnt_keyexchange(self):
		hsk = handshake.constuct_clnt_keyexchange(self.svr_pubkey,self.premaster)
		self.hsk_messages += hsk
		rcrd = record.wrap_record(hsk,record.RECORD_TYPE_HSK)
		self.send(rcrd)
		return

	def send_change_cipher_spec(self):
		c = ccs.constuct_change_cipherspec()
		self.seq_int = 0
		rcrd = record.wrap_record(c,record.RECORD_TYPE_CCS)
		self.send(rcrd)
		return  

	def send_finish(self):
		finish = handshake.constuct_finish(self.master,self.hsk_messages)
		protected = self.protect_payload(finish,record.RECORD_TYPE_HSK)
		finish_record = record.wrap_record(protected,record.RECORD_TYPE_HSK)
		self.send(finish_record)
		return

	def send_app_data(self, data):
		protected = self.protect_payload(data,record.RECORD_TYPE_APP)
		appdata_record = record.wrap_record(protected,record.RECORD_TYPE_APP)
		self.send(appdata_record)
		return

	def protect_payload(self,data,record_t):
		"""
			MTE : mac then encrypt
			rfc 5246 6.2.3.1 and 6.2.3.2
		"""
		if self.cipher_algr == keys.CIPHER_AES128 or self.cipher_algr == keys.CIPHER_NULL:
			seq_bytes = struct.pack(">q",self.seq_int)
			length = struct.pack(">h",len(data))
			hmac_code = keys.ssl_mac_sha(self.clnt_w_mackey, seq_bytes, record_t, record.RECORD_VERSION, length,data)
			padded = keys.pad(data+hmac_code,self.cipher_algr)
			encrypted = keys.encrypt_payload(self.clnt_encrkey,padded,self.cipher_algr)
		else:
			raise Exception("blocking mode not supported")

		self.seq_int += 1
		return encrypted

	def generate_keys(self):
		self.premaster = self.clnt_version + b"\x02"*46  #rfc 52467.4.7.1
		self.master = keys.generate_master(self.premaster,self.clnt_random,self.svr_random)
		clnt_w_mackey,svr_w_mackey,clnt_encrkey,svr_encrkey = keys.generate_cipher_hmac(self.master,self.clnt_random,self.svr_random)
		self.clnt_w_mackey = clnt_w_mackey
		self.svr_w_mackey = svr_w_mackey
		self.clnt_encrkey = clnt_encrkey
		self.svr_encrkey = svr_encrkey
		return

	def get_server_hellos(self):
		buf = b""
		while 1:
			buf += self.recv(8192)
			records = record.get_some_record(buf,3)
			if records != None:
				break

		self.svr_random = handshake.get_svrhello_random(records[0])
		self.svr_pubkey = handshake.get_svrcert_pubkey(records[1])

		self.hsk_messages += records[0][5:]
		self.hsk_messages += records[1][5:]
		self.hsk_messages += records[2][5:]

		return records

	def get_server_ccs_finish(self):
		buf = b""
		flag = ""
		while 1:
			buf += self.recv(8192)
			while 1:
				rcrd, buf = record.pop_one_record(buf)
				if rcrd == None:
					break

				if rcrd[0:1] == record.RECORD_TYPE_CCS:
					flag = "got ccs"
					print("got ccs")
				if flag == "got ccs" and rcrd[0:1] == record.RECORD_TYPE_HSK:
					print("got finish")
					return buf

	def get_app_data(self):
		buf = b""
		while 1:
			buf += self.recv(8192)
			rcrd, buf = record.pop_one_record(buf)
			if rcrd != None:
				break
		
		if rcrd[0:1] != record.RECORD_TYPE_APP:
			raise Exception("did not recv an app data record")

		if self.cipher_algr == keys.CIPHER_NULL:
			return rcrd[5:-20].decode()
		elif self.cipher_algr == keys.CIPHER_AES128:
			return keys.decrypt_ciphertext(self.svr_encrkey,rcrd[5:],self.cipher_algr)
		else:
			raise Exception("not supported")