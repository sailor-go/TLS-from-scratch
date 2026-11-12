
import sys
import socket
import DemoTLS12
from pprint import pprint


APP_DATA_REQUEST = b"GET / HTTP/1.0\r\n\r\n"

if  "__main__" == __name__:
	try:
		ip = sys.argv[1]
		port = int(sys.argv[2])
		cipher_suite = sys.argv[3]
		if cipher_suite not in DemoTLS12.CIPHER_LIST:
			raise Exception
	except:
		print("argv error, example: python xxx.py 1.1.1.1 443 AES-SHA")
		sys.exit()


	ssl = DemoTLS12.DemoTLS12(cipher_suite)
	ssl.connect((ip,port))

	ssl.send_clienthellos()

	ssl.get_server_hellos()  

	ssl.generate_keys()

	ssl.send_clnt_keyexchange()
	ssl.send_change_cipher_spec()
	ssl.send_finish()

	ssl.get_server_ccs_finish()

	ssl.send_app_data(APP_DATA_REQUEST)
	print("\r\nsend request:\r\n" + APP_DATA_REQUEST.decode())

	response = ssl.get_app_data()
	print("\r\nrecv response:\r\n" + response)

	ssl.close()

	print("exiting, bye")
