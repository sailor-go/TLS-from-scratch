#include <stdio.h>
#include <winsock2.h>
#include "ssl.h"
#include "err.h"
#include "inc.h"

#define RESPONSE "HTTP/1.1 200 OK\r\nContent-type:text/html\r\nContent-length:17\r\n\r\ni wish you happy."


SSL_CTX *init_ctx()
{
	SSL_CTX *ctx;
	FILE *file;
	X509 *cert = NULL;

	ctx = SSL_CTX_new(SSLv23_method());
	if(!ctx)
	{
		LOG_ERR;
		return NULL;
	}

	SSL_CTX_set_tmp_dh_callback(ctx,pub_dh_callback);
	SSL_CTX_set_cipher_list(ctx,"ALL");
	SSL_CTX_set_options(ctx,SSL_OP_ALL | SSL_OP_NO_TLSv1_3);//ban tls1.3 is just to demonstrate tls1.2

	if(SSL_CTX_use_certificate_file(ctx,"../../misc/server.crt", SSL_FILETYPE_PEM) != 1)
	{
		LOG_ERR;
		SSL_CTX_free(ctx);
		return NULL;
	}
	if(SSL_CTX_use_PrivateKey_file(ctx,"../../misc/server.key", SSL_FILETYPE_PEM) != 1)
	{
		LOG_ERR;
		SSL_CTX_free(ctx);
		return NULL;
	}
	file = fopen("../../misc/intermediate.crt","r");
	PEM_read_X509(file,&cert,NULL,NULL);
	fclose(file);
	if(1 != SSL_CTX_add_extra_chain_cert(ctx, cert))
	{
		LOG_ERR;
	}
	if(SSL_CTX_check_private_key(ctx) != 1)
	{
		LOG_ERR;
		SSL_CTX_free(ctx);
		return NULL;
	}
	return ctx;
}
void handle_connection(SSL_CTX *ctx, int fd)
{
	SSL *ssl;
	unsigned long ulerror;
	int ret,ierror;
	char buf[1024] = {0};

	ssl = SSL_new(ctx);
	if(!ssl)
	{
		LOG_ERR;
		return;
	}

	if( 0 == SSL_set_fd(ssl,fd))
	{
		LOG_ERR;
		SSL_free(ssl);
		return;
	}

	ERR_clear_error();
	ret = SSL_accept(ssl);
	if(1 != ret)
	{
		ulerror = ERR_get_error();
		ERR_error_string_n(ulerror,buf,1023);
		printf("\r\naccept error:%d  %s",ulerror,buf);
		return;
	}

	while(1)
	{
		ERR_clear_error();
		ret = SSL_read(ssl,buf,1023);
		if(ret <= 0)
		{
			ierror = SSL_get_error(ssl,ret);
			if (SSL_ERROR_WANT_READ == ierror || SSL_ERROR_WANT_WRITE == ierror)
			{
				continue;
			}
			printf("\r\nssl read error: %d ",ierror);
			SSL_free(ssl);
			return;
		}
		else
		{
			buf[ret] = 0;
			printf("read data: %s",buf);
			break;
		}
	}

	pub_send_app_data(ssl,RESPONSE,strlen(RESPONSE));
}

void serve_forever(unsigned int port)
{
	int listening,fd;
	unsigned long error;
	int ret;
	struct sockaddr_in addr = {0};
	WSADATA wsaData;
	char buf[1024] = {0};
	SSL_CTX *ctx;

	if(WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
	{
		LOG_ERR;
		return ;
	}

	ctx = init_ctx();
	if(!ctx)
	{
		LOG_ERR;
		return;
	}

	listening = socket(AF_INET, SOCK_STREAM, 0);
	if(listening == -1)
	{
		LOG_ERR;
		SSL_CTX_free(ctx);
		return;
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(0);

	ret = bind(listening,(struct sockaddr *)&addr, sizeof(struct sockaddr));
	if(0 != ret)
	{
		LOG_ERR;
		SSL_CTX_free(ctx);
		return;
	}

	ret = listen(listening,20);
	if(0!=ret)
	{
		LOG_ERR;
		SSL_CTX_free(ctx);
		return;
	}

	ret = sizeof(struct sockaddr);
	while(fd = accept(listening, (struct sockaddr *)&addr, &ret))
	{
		if(INVALID_SOCKET == fd)
		{
			LOG_ERR;
			continue;
		}

		printf("\r\n*************  established a new tcp connection  ************");
		handle_connection(ctx,fd);
		closesocket(fd);
	}
	return;
}

int main(int argc,char *argv[])
{
	unsigned int port;
	{
		if(2 != argc)
		{
			printf("\r\nargs: port");
			return 1;
		}
		sscanf(argv[1],"%5d",&port);

		if(port > 65535)
		{
			printf("\r\nerror:third argment is not a valid port");
			return 1;
		}
	}

	printf("\r\ni am compile with OpenSSL %s header file",OPENSSL_VERSION_TEXT);
	printf("\r\nlink with %s library",OpenSSL_version(OPENSSL_VERSION));
	printf("\r\ni will response in http style with any request.");

	pub_ssllib_init();

	serve_forever(port);

	printf("\r\nbye~");
	return 0;
}