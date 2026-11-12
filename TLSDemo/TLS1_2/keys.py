import hmac
import hashlib
import random
from Crypto.Cipher import AES
import struct

LABEL_MASTER_SECRET = b"master secret"
LABEL_KEY_EXPANSION = b"key expansion"
LABEL_FINISHED      = b"client finished"

MAC_KEY_LENGTH_SHA = 20
AES128_KEY_LENGTH = 16

CIPHER_NULL = "NULL"
CIPHER_AES128 = "AES128"

HMAC_SHA = "SHA"

def random_octets(length):
	octets=b""
	for _ in range(length):
		c = struct.pack("B",random.randint(0,0xff))
		octets += c
	return octets

def sha256(data):
	m = hashlib.sha256()
	m.update(data)
	return m.digest()

def hmac_sha256(secret,seed):
	h = hmac.new(secret,seed,digestmod= "SHA256")
	return h.digest()

def hmac_sha(secret,seed):
	h = hmac.new(secret,seed,digestmod= "SHA1")
	return h.digest()

def A(secret,seed,i):
	if i == 0:
		return seed
	else:
		return hmac_sha256(secret,A(secret,seed,i-1))

def P_SHA256(secret,seed):
	"""
	rfc 5246 chapter 5
	128 byte is enough. rfc 5246 6.3
	"""

	p_hash = hmac_sha256(secret,A(secret,seed,1)+seed) + \
	hmac_sha256(secret,A(secret,seed,2)+seed) + \
	hmac_sha256(secret,A(secret,seed,3)+seed) + \
	hmac_sha256(secret,A(secret,seed,4)+seed)

	return p_hash

def PRF_SHA256(secret,lable,seed):
	return P_SHA256(secret, lable+seed)

def generate_master(premaster,clnt_random,svr_random):
	"""
	rfc 5246 8.1
	"""
	master = PRF_SHA256(premaster, LABEL_MASTER_SECRET, clnt_random + svr_random)[0:48]

	return master

def generate_cipher_hmac(master,clnt_random,svr_random):
	key_block = PRF_SHA256(master,LABEL_KEY_EXPANSION,svr_random+clnt_random)

	client_write_mac_key = key_block[0:MAC_KEY_LENGTH_SHA]
	key_block = key_block[MAC_KEY_LENGTH_SHA:]

	server_write_mac_key = key_block[0:MAC_KEY_LENGTH_SHA]
	key_block = key_block[MAC_KEY_LENGTH_SHA:]

	client_write_encrypt_key = key_block[0:AES128_KEY_LENGTH]
	key_block = key_block[AES128_KEY_LENGTH:]

	server_write_encrypt_key = key_block[0:AES128_KEY_LENGTH]
	key_block = key_block[AES128_KEY_LENGTH:]

	return client_write_mac_key,server_write_mac_key,client_write_encrypt_key,server_write_encrypt_key

def get_finished_verify_data(master,hsk_messages,verify_data_len):
	h = sha256(hsk_messages)  #rfc5246 7.4.9
	verify_data = PRF_SHA256(master,LABEL_FINISHED,h)[0:verify_data_len]
	return verify_data

def ssl_mac_sha(key,seq, t, version, length, fragment):
	return hmac_sha(key, seq+t+version+length+fragment)

def encrypt_payload(key,payload,cipher_algr):
	if cipher_algr == CIPHER_AES128: 
		#rfc5246 6.2.3.2 cbc block cipher
		iv = random_octets(16)
		print(len(iv))
		aes = AES.new(key,AES.MODE_CBC)
		cipher_text = aes.encrypt(iv+payload)
		return cipher_text
	elif cipher_algr ==   CIPHER_NULL:
		return payload   #rfc5246 6.2.3.1 null or stream cipher
	else:
		print("%s %d" % (__FILE__,__LINE__) + "stranger cipher")
		raise Exception

def pad(data,cipher_algr):
	if cipher_algr == CIPHER_AES128:
		#cbc block cipher, rfc 5246 6.2.3.2
		#block len of aes is 16
		data_len = len(data) + 1
		pad_len = ((~data_len) & 0xf) + 1
		pad = chr(pad_len).encode() * (pad_len+1) #including padding and padding_length
		padded = data + pad
		return padded
	elif cipher_algr ==   CIPHER_NULL:
		return data #no need to pad in stream and null, rfc 5246 6.2.3.1 
	else:
		raise Exception("stranger cipher")

def decrypt_ciphertext(key,cipher_text,cipher_algr):
	if cipher_algr == CIPHER_AES128:
		aes = AES.new(key,AES.MODE_CBC)
		decrypted = aes.decrypt(cipher_text)
		padding_length = decrypted[-1]
		content = decrypted[16:-padding_length-1-20]
		return content.decode()
	elif cipher_algr == CIPHER_AES128:
		return rcrd[5:-20].decode()
	else:
		raise Exception("not supported")
