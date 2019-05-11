# 安全协议实验报告

2016级网络空间安全 刘成 201600301255

### 实验一 证书解析

##### 实验要求

利用OPENSSL或其他密码库（如python,go等)，编写一个解码[X.509](http://X.509)数字证书的程序，能够解析证书中的基本ASN1项内容并打印输出。

##### 实验过程

​		1.从浏览器中导出任意一个数字证书

​		2.编写程序，对证书进行解析

##### 实验代码

```python
import OpenSSL
from dateutil import parser

cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open("ChambersofCommerceRoot-2008.crt").read())
certIssue = cert.get_issuer()

print ("证书版本:            ",cert.get_version() + 1)

print ("证书序列号:          ",hex(cert.get_serial_number()))

print ("证书中使用的签名算法: ",cert.get_signature_algorithm().decode("UTF-8"))

print ("颁发者:              ",certIssue.commonName)

datetime_struct = parser.parse(cert.get_notBefore().decode("UTF-8"))

print ("有效期从:             ",datetime_struct.strftime('%Y-%m-%d %H:%M:%S'))

datetime_struct = parser.parse(cert.get_notAfter().decode("UTF-8"))

print ("到:                   ",datetime_struct.strftime('%Y-%m-%d %H:%M:%S'))

print ("证书是否已经过期:      ",cert.has_expired())

print("公钥长度" ,cert.get_pubkey().bits())

print("公钥:\n" ,OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()).decode("utf-8"))

print("主体信息:")

print("CN : 通用名称  OU : 机构单元名称")
print("O  : 机构名    L  : 地理位置")
print("S  : 州/省名   C  : 国名")

for item in certIssue.get_components():
    print(item[0].decode("utf-8"), "  ——  ",item[1].decode("utf-8"))

print(cert.get_extension_count())
```

##### 实验结果

证书版本:             3
证书序列号:           0xa3da427ea4b1aeda
证书中使用的签名算法:  sha1WithRSAEncryption
颁发者:               Chambers of Commerce Root - 2008
有效期从:              2008-08-01 12:29:50
到:                    2038-07-31 12:29:50
证书是否已经过期:       False
公钥长度 4096
公钥:
 -----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArwDLcDcrgFpKOmx4lH2j
fxof9jXVvdvLDURyPiaykFK6YzsoWG+ls22UpvPdZAxV9vbn8iIigF7hYsa2KeGB
bPK/5X0yalSgMhlZ/h+L1z1ghoUkb+MRs3c+IJY1IWuzCNlwLmT3hJJT1g6wkIqK
44eNBtO9kA7imaEbhg7amgq7C2FQBlLxnn927MsP0B4Nz5kwPRzERRBYrNbT6Nfl
6sUBB3fWUeYDf4pIpU1odbnpvJ5OGXH1MkucbWAZC/vMnXXcvybNj5N4OXlzXiUO
ylzrdxIHy2RBR3KTq1DD6wl2ZDTSObd2EQkNdkXEqa49aq+1fWUvlFgQ7Fx8r37i
thjZ0JtOWknfqWYLzDzGeHynnB3jzo5TvgXeYA9r5RrbP+PhIckpwfHrB5xSGwFE
UTx7JdfE5VJUXSUHyhYguK3kQe56CP6Zb4OmkQKwbDZVaud99ZbmyoHWl/GUg+nt
sLFrEmkerPtdqcWY6bRbWHq+PaJEOmNZ1Asl3htPveUBns3SKdWfFxkKb78MkNMJ
X9njijXMeVpNGTeSt8TBra/0eSSasgELsa9clvOAMvtcPZjxoD9K3r6vlC7ZVZoX
bmCdY2y4Y8mugVwYNeCQu748TzciuX7rz553IaY9OIH7SNoxPSvjifXQtb1+4FDE
EomzI5oQMYXbrm/vODMYdhECAwEAAQ==
-----END PUBLIC KEY-----

主体信息:
CN : 通用名称  OU : 机构单元名称
O  : 机构名    L  : 地理位置
S  : 州/省名   C  : 国名
C   ——   EU
L   ——   Madrid (see current address at www.camerfirma.com/address)
serialNumber   ——   A82743287
O   ——   AC Camerfirma S.A.
CN   ——   Chambers of Commerce Root - 2008
5



### 实验二 ssl通信模拟

##### 实验要求

利用openssl开源库（或其他开源实现），编写一个c/s应用要求客户端能输入任意消息，服务器端能将该消息显示，或者记录到文件中。

##### 实验过程

1.使用openssl生成实验所用的证书

2.编写客户端和服务器端代码

3.运行测试，分析结果

##### 实验代码

生成证书：

```
openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem
```

client.py

```python
import socket, ssl, pprint

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_s=ssl.wrap_socket(s,cert_reqs=ssl.CERT_REQUIRED, ca_certs="cert.pem")
ssl_s.connect(("127.0.0.1", 8000))
print("套接字连接成功")
data = input()
while data != "":
    ssl_s.send(bytearray(data, encoding="utf-8"))
    print("成功发送数据")
    data = input()

print("生成的证书信息")
pprint.pprint(ssl_s.getpeercert())
ssl_s.close()
```

server.py

```python
import socket
import ssl

sock = socket.socket()
print("建立套接字成功")
sock.bind(("127.0.0.1", 8000))
print("绑定成功")
sock.listen(1)


def input_pro(data):
    print("接收到的客户端数据长度是", len(data))
    print("内容：", data.decode(encoding="utf-8"))
    return True


def doclient(connstream):
    data = connstream.recv(1024)
    while data:
        if not input_pro(data):
            break
        data = connstream.recv(1024)
        print("接收到的数据：", data)
    return True


while True:
    # 接受连接并返回（conn,address）,
    # 其中conn是新的套接字对象，
    # 可以用来接收和发送数据。
    # address是连接客户端的地址。
    conn,addr=sock.accept()
    print("客户端的套接字数据接收到了:")
    connstream = ssl.wrap_socket(conn, "key.pem", "cert.pem", server_side=True)
    try:
        doclient(connstream)
    finally:
        connstream.shutdown(socket.SHUT_RDWR)
        connstream.close()
```

##### 实验结果



