
import time
import struct
import cryptography.x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
import keys


HSK_TYPE_CLIENT_HELLO  = b"\x01"
HSK_TYPE_CLIENT_KEY_EX = b"\x10" 
HSK_TYPE_FINISHED = b"\x14"

HSK_VERSION = b"\x03\x03"

COMPRESS_METHOD_NULL = b"\x00"

VERIFY_DATA_LEN = 12   #for NULL-SHA and AES-SHA, rfc 5246  7.4.9


def constuct_clnthello(cipher_suite):
	gmt = struct.pack(">i",int(time.time()))
	random = b"\x01"*28   #it is not pseudo random, it is fake random
	sess_id = b"\x00"
	cipher_suite_len = struct.pack(">h",len(cipher_suite))
	compress_method = COMPRESS_METHOD_NULL
	compress_method_len = struct.pack(">b",len(compress_method))
	hsk_len = len(HSK_VERSION + gmt + random + sess_id + cipher_suite_len + cipher_suite + compress_method_len + compress_method)
	hsk_len = struct.pack(">i",hsk_len)[1:]

	hsk = HSK_TYPE_CLIENT_HELLO + hsk_len + HSK_VERSION + gmt + random + sess_id + cipher_suite_len + cipher_suite + compress_method_len + compress_method
	return hsk, gmt+random, HSK_VERSION

def constuct_clnt_keyexchange(key,premaster):
	"""
	this function is specially for RSA key exchange
	"""
	premaster_encrypted = key.encrypt(premaster,PKCS1v15())

	key_bytes = int(key.key_size/8)
	premaster_encrypted_len = struct.pack(">h",key_bytes)
	hsk_len = 2 + key_bytes
	hsk_len = struct.pack(">i",hsk_len)[1:]

	hsk = HSK_TYPE_CLIENT_KEY_EX + hsk_len + premaster_encrypted_len + premaster_encrypted
	return hsk

def constuct_finish(master,hsk_messages):
	verify_data = keys.get_finished_verify_data(master,hsk_messages,VERIFY_DATA_LEN)
	verify_len = struct.pack(">i",VERIFY_DATA_LEN)[1:]
	finished = HSK_TYPE_FINISHED + verify_len + verify_data
	return finished

def get_svrhello_random(svrhello_record):
	random = svrhello_record[11:11+32]
	return random

def get_svrcert_pubkey(cert_record):
	(cert_len,) = struct.unpack(">i",b"\x00"+cert_record[12:15])
	cert = cert_record[15:15+cert_len]
	cert = cryptography.x509.load_der_x509_certificate(cert,default_backend())
	#help(cert.public_key())
	#print(cert.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.PKCS1))
	return cert.public_key()
	

