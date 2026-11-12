import struct
from pprint import pprint
import keys

RECORD_TYPE_HSK = b"\x16"
RECORD_TYPE_CCS = b"\x14"
RECORD_TYPE_APP = b"\x17"
RECORD_VERSION  = b"\x03\x03" #tls 1.2

def wrap_record(cont,cont_type):
	length = struct.pack(">h",len(cont))	
	record = cont_type + RECORD_VERSION + length + cont
	return record

def get_some_record(buf,num):
	records = []
	for _ in range(num):
		if len(buf)<5:
			return None

		rcrd_t,rcrd_v,rcrd_l = struct.unpack(">bhh",buf[0:5])
		if rcrd_l + 5 > len(buf):
			return None

		records.append(buf[0:5+rcrd_l]) 
		buf = buf[5+rcrd_l:]

	if b"" != buf:
		print("get_some_record: parsing error")

	return records

def pop_one_record(buf):
	"""
	return a record and the rest of buf
	"""
	if len(buf)<5:
		return None,buf

	rcrd_t,rcrd_v,rcrd_l = struct.unpack(">bhh",buf[0:5])
	if rcrd_l + 5 > len(buf):
		return None,buf

	rcrd = buf[0:5+rcrd_l]
	rest = buf[5+rcrd_l:]

	return rcrd, rest

