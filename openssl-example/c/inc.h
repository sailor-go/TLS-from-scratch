
#define FAIL -1
#define AGAIN 0

#define LOG_ERR printf("\r\nerror. file:%s  function:%s  line:%d",__FILE__,__FUNCTION__,__LINE__)

extern int pub_ssllib_init();
extern int pub_send_app_data(SSL *ssl, char *buf, unsigned int len);
extern DH * pub_dh_callback(SSL *ssl, int is_export, int keylength);