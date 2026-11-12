#include "ssl.h"
#include <winsock2.h>
#include "err.h"
#include "inc.h"
#include "bio.h"

#define DH2048  "-----BEGIN DH PARAMETERS-----\
MIIBCAKCAQEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb\
IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft\
awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT\
mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh\
fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq\
5RXSJhiY+gUQFXKOWoqsqmj//////////wIBAg==\
-----END DH PARAMETERS-----"  //RFC 3526
DH *pub_get_dh2048()
{
	DH *dh;
	BIO *bio;

	bio = BIO_new_mem_buf(DH2048,strlen(DH2048));
	if(!bio)
	{
		LOG_ERR;
		return NULL;
	}
	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	if(!bio)
	{
		LOG_ERR;
	}
	BIO_free(bio);
	return dh;
}

DH * pub_dh_callback(SSL *ssl, int is_export, int keylength)
{
	return pub_get_dh2048();
}

int pub_ssllib_init()
{
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	return 0;
}

int pub_send_app_data(SSL *ssl, char *data, unsigned int len)
{
	int ret;
	unsigned int sent = 0;
	while(sent < len)
	{
		//for blocking underlying BIO, the data is surely sent by SSL_write
		//for non blocking io, we need this loop, though you are suggested to use select/epoll
		ERR_clear_error();
		ret = SSL_write(ssl, data+sent, len);
		if(ret <= 0)
		{
			char buf[1024] = {0};
			unsigned long error = ERR_get_error();
			if (SSL_ERROR_WANT_READ == error || SSL_ERROR_WANT_WRITE == error)
			{
				break;
			}
			ERR_error_string_n(error,buf,1023);
			printf("\r\n%d   %s",error,buf);
			return FAIL;
		}
		else
		{
			sent += ret;
		}
	}
	return ret;
}



