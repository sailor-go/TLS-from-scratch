## 简介

实现了极简的TLS协议，可以帮助理解TLS的机制。

使用python3.

依赖Crypto（pycryptodome）、cryptography模块。

## 使用方法

只支持AES128-SHA、NULL-SHA两个算法套件。

服务器可以使用openssl工具来模拟：

.\openssl-1.1.1c-mingw-w64\openssl.exe s_server -port 8443 -cipher ALL:eNULL@SECLEVEL=0 -cert .\misc\server.crt -key .\misc\server.key -www

客户端：

 python .\TLS1_2\main.py X.X.X.X 443 AES128-SHA

## 实现

main.py：一个应用例子

DemoTLS12.py：实现ssl的原始api

handshake.py:和握手有关的message等

ccs.py：change cipher spec

record.py：ssl记录相关代码

keys.py：密钥计算相关，prf、hmac、cipher等。



## 其他

此项目只是为了展示TLS的工作原理，代码实现上没有考虑安全性，例如不会对报文和对端进行校验。

简单起见，假设总是客户端先发送应用数据。在get_server_ccs_finish的逻辑中，如果服务端先发送了应用数据，则返回没有解析socket 流数据（buf），但这个buf并没有被处理。