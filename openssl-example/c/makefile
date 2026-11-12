CC = gcc.exe
LD = gcc.exe

SERVER_SOURCE = server.c pub.c
CLIENT_SOURCE = client.c pub.c

SSL_INC	 = ../../openssl-1.1.1c-mingw-w64/openssl
LIB_PATH = ../../openssl-1.1.1c-mingw-w64

app:
	$(CC) -g3 -o client.exe $(CLIENT_SOURCE) -L $(LIB_PATH) -lssl -lcrypto -lws2_32  -lgdi32 -I $(SSL_INC)
	$(CC) -g3 -o server.exe $(SERVER_SOURCE) -L $(LIB_PATH) -lssl -lcrypto -lws2_32  -lgdi32 -I $(SSL_INC)

clean:
	rm *.exe