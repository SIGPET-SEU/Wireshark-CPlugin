## vmess+tcp+tls原理

![image.png](attachment:c8409028-f1d6-469f-b373-df1f78c18e96:image.png)

<aside>
💡

将传输协议改为ws即可成为vmess+ws+tls

</aside>

### vmess协议

数据部分：“信息”为vmess式的协议的数据

协议头部分：选择”zero“作为加密方式，即对这一数据内容不进行加密

![image.png](attachment:b351e969-07cc-4141-b544-e9d574b26c63:image.png)

<aside>
💡

“none”和“zero”的区别

两者都不会对数据内容进行加密，但”none“会对vmess数据包进行校验，影响性能。

</aside>

vmess协议的协议头部分在任何时候都是要进行加密的，“额外ID:0”表示协议头的加密方式使用AEAD

![image.png](attachment:5d0b87c5-ab18-4a0b-a6a5-acb92997d209:image.png)

头部还会填充一些AEAD用到的解密的密钥，即形成vmess协议处理后的数据格式

![image.png](attachment:9dea6e3e-6b62-4ba4-a1f7-e72700886b91:image.png)

此时数据部分未进行加密，直接传输会被防火墙阻拦，需要再套一层tls加密

### tls加密

客户端v2ray和服务器v2ray建立一个tls连接，建立好的连接就会使用tls对此串数据进行加密

![image.png](attachment:6f685386-3273-4e7e-ab35-fddc4367827a:image.png)

整个vmess协议都会进行加密，加密后的数据的前面会套一个头部，头部内容为tls证书的域名

数据从客户端发送至网络，防火墙会视其为正常的https流量，放行至服务器端，并通过层层解密：

![image.png](attachment:7d5122b7-fd8d-4bd8-983c-e268de3fc80e:image.png)

### 传输协议承载

https：http+tls                                      vmess+ws（ws是基于tcp的）          vmess+ws+tls

![image.png](attachment:5389bcc7-e265-4d4c-81c3-32968c8f95b8:image.png)

![image.png](attachment:910815b9-fd86-47a6-bd09-bc45ddef38e9:image.png)

![image.png](attachment:c1f96ee1-655c-4f8e-8370-ffd3f9fa939a:image.png)
