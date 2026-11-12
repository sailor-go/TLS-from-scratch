#include <stdio.h>
#include <winsock2.h>
#include "ssl.h"
#include "err.h"
#include "inc.h"

#define REQUST 	"GET / HTTP/1.1\r\nUser-Agent:happyagency\r\n\r\n"
#define REQUST2 "GET /nothing?word=youfakeserver HTTP/1.1\r\nUser-Agent:you are not wellcome\r\n\r\n"

typedef struct 
{
	SSL *ssl;
	int fd;
	unsigned int verify_errors;
}client_app_sess_t;

int ssl_ex_data_id;
enum{
	VERIFY_SIG_ERROR = 0X01
};

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	SSL *ssl;
	client_app_sess_t * app;
	int err;
	if(preverify_ok == 1)
	{
		return 1;
	}

	ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	app = SSL_get_ex_data(ssl, ssl_ex_data_id);
	if (app == NULL)
	{
		LOG_ERR;//here worth an assert.
		return 0;
	}

	err = X509_STORE_CTX_get_error(x509_ctx);
	printf("\r\ncert verifying issue: %d  %s.",err, X509_verify_cert_error_string(err));

	//this switch seems like a blacklist, its not recommende
	switch(err)
	{
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			app->verify_errors |= VERIFY_SIG_ERROR;
			break;
		default:
			//clear this error?
			printf(" ignore this issue.");
			break;
	}
	
	return 1;//always continue the handshake, handle the verify issue in application
}

SSL_CTX *init_client_ctx()
{
	SSL_CTX *ctx;
	unsigned long ulerror;
	int ret;
	char buf[1024]={0};

	ctx = SSL_CTX_new(SSLv23_method());
	if(!ctx)
	{
		ulerror = ERR_get_error();
		ERR_error_string_n(ulerror,buf,1023);
		printf("%d  %s",ulerror,buf);
		LOG_ERR;
		return NULL;
	}
	SSL_CTX_set_options(ctx,SSL_OP_ALL | SSL_OP_NO_TLSv1_3);//ban tls1.3 is just to demonstrate tls1.2
	if(1 != SSL_CTX_set_cipher_list(ctx,"ALL"))
	{
		LOG_ERR;
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	SSL_CTX_set_verify_depth(ctx, 2);//peer, intermediate ca, root ca
	if (1 != SSL_CTX_load_verify_locations(ctx, "..\\..\\misc\\root.crt", NULL))
	{
		LOG_ERR;
	}

	ssl_ex_data_id = SSL_CTX_get_ex_new_index(0, "client app ex data", NULL, NULL, NULL);

	return ctx;
}

int client(SSL_CTX *ctx, unsigned long ip, unsigned int port)
{
	unsigned long ulerror;
	int ret;
	struct sockaddr_in addr = {0};
	WSADATA wsaData;
	char buf[1024]={0};
	int timeout = 100000;
	client_app_sess_t app_sess = {0};// this sess lives in stack

	app_sess.ssl = SSL_new(ctx);
	if(!app_sess.ssl)
	{
		LOG_ERR;
		SSL_CTX_free(ctx);
		return 1;
	}

	SSL_set_ex_data(app_sess.ssl, ssl_ex_data_id, &app_sess);

	app_sess.fd = socket(AF_INET, SOCK_STREAM, 0);
	if(app_sess.fd == 0)
	{
		LOG_ERR;
		SSL_free(app_sess.ssl);
		SSL_CTX_free(ctx);
		return 1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(ip);

	setsockopt(app_sess.fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

	ret = connect(app_sess.fd, (struct sockaddr *)&addr, sizeof(struct sockaddr));
	if(ret == -1)
	{
		LOG_ERR;
		SSL_free(app_sess.ssl);
		SSL_CTX_free(ctx);
		closesocket(app_sess.fd);
		return -1;
	}

	if(0 == SSL_set_fd(app_sess.ssl, app_sess.fd))
	{
		LOG_ERR;
		SSL_free(app_sess.ssl);
		SSL_CTX_free(ctx);
		closesocket(app_sess.fd);
		return 1;
	}

	ERR_clear_error();
	ret = SSL_connect(app_sess.ssl);
	if (1 != ret)
	{
		printf("\r\n ssl connect failed, return %d",ret);
		ulerror = ERR_get_error();
		ERR_error_string_n(ulerror,buf,1023);
		printf("%d  %s",ulerror,buf);
		SSL_free(app_sess.ssl);
		SSL_CTX_free(ctx);
		closesocket(app_sess.fd);
		return 1;
	}

	
	//if(SSL_get_verify_result(app_sess.ssl) != X509_V_OK || SSL_get_peer_certificate(app_sess.ssl) == NULL)
	if(app_sess.verify_errors)
	{
		printf("\r\nthe peer certificate is not trust worthy.");
		pub_send_app_data(app_sess.ssl, REQUST2, strlen(REQUST2));
	}
	else
	{
		pub_send_app_data(app_sess.ssl, REQUST, strlen(REQUST));
	}
	
	while(1)
	{
		int ierror;
		ERR_clear_error();
		ret = SSL_read(app_sess.ssl,buf,1023);
		if(ret <= 0)
		{
			ierror = SSL_get_error(app_sess.ssl,ierror);
			if (SSL_ERROR_WANT_READ == ierror || SSL_ERROR_WANT_WRITE == ierror)
			{
				continue;
			}
			printf("\r\nssl read error: %d ",ierror);
			break;
		}
		else
		{
			buf[ret] = 0;
			printf("\r\nread data: %s",buf);
		}
	}

	SSL_shutdown(app_sess.ssl);
	SSL_free(app_sess.ssl);
	closesocket(app_sess.fd);
	return 0;
}

int main(int argc,char *argv[])
{
	SSL_CTX *ctx;
	unsigned int ip1,ip2,ip3,ip4;
	unsigned int port;
	unsigned long ip;
	struct sockaddr_in addr = {0};
	WSADATA wsaData;

	{
		if(3 != argc)
		{
			printf("\r\nargs:ipv4 port");
			return 1;
		}

		sscanf(argv[1],"%d.%d.%d.%d",&ip1,&ip2,&ip3,&ip4);
		if(ip1>255 || ip2>255 || ip3>255 || ip4>255)
		{
			printf("\r\nerror:second argment is not a valid ipv4 string");
			return 1;
		}
		ip = (ip1<<24) + (ip2<<16) + (ip3<<8) + ip4;

		sscanf(argv[2],"%5d",&port);

		if(port > 65535)
		{
			printf("\r\nerror:third argment is not a valid port");
			return 1;
		}
	}

	printf("\r\ni am compile with OpenSSL %s header file",OPENSSL_VERSION_TEXT);
	printf("\r\nlink with %s library",OpenSSL_version(OPENSSL_VERSION));
	printf("\r\ni will send a http request an print the response");

	if(WSAStartup(MAKEWORD(2,2),&wsaData)!=NO_ERROR)
	{
		LOG_ERR;
		return 1;
	}

	pub_ssllib_init();

	if((ctx = init_client_ctx()) == NULL)
	{
		LOG_ERR;
		return 1;
	}

	client(ctx, ip, port);

	printf("\r\nbye~");
	return 0;
}