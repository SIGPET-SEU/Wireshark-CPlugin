## vmess+tcp+tls原理

![image](https://github.com/user-attachments/assets/3e9def8b-f723-4d4c-baf5-2389d31c4c4a)



<aside>
💡将传输协议改为ws即可成为vmess+ws+tls

</aside>

### vmess协议

数据部分：“信息”为vmess式的协议的数据

协议头部分：选择”zero“作为加密方式，即对这一数据内容不进行加密

![image](https://github.com/user-attachments/assets/b7591d4a-f40f-4574-b1f9-35ce9ee48098)

<aside>
💡“none”和“zero”的区别

两者都不会对数据内容进行加密，但”none“会对vmess数据包进行校验，影响性能。

</aside>

vmess协议的协议头部分在任何时候都是要进行加密的，“额外ID:0”表示协议头的加密方式使用AEAD

![image](https://github.com/user-attachments/assets/b4eec94b-4bdb-4ad5-a085-d70f4f957547)

头部还会填充一些AEAD用到的解密的密钥，即形成vmess协议处理后的数据格式

![image](https://github.com/user-attachments/assets/c3e7909b-cefd-4baf-a24d-22ed5debd99c)

此时数据部分未进行加密，直接传输会被防火墙阻拦，需要再套一层tls加密

### tls加密

客户端v2ray和服务器v2ray建立一个tls连接，建立好的连接就会使用tls对此串数据进行加密

![image](https://github.com/user-attachments/assets/2898be1a-b0ed-4d7f-bd6f-9ba9c648f36e)

整个vmess协议都会进行加密，加密后的数据的前面会套一个头部，头部内容为tls证书的域名

数据从客户端发送至网络，防火墙会视其为正常的https流量，放行至服务器端，并通过层层解密得到：

![image](https://github.com/user-attachments/assets/587b8fd8-5441-4539-81f1-3d6c8ab5ddae)

### 传输协议承载

vmess+ws（ws是基于tcp的）

![image](https://github.com/user-attachments/assets/3cd7bda6-2034-4e76-9a4b-80b9ce428e01)

vmess+ws+tls

![image](https://github.com/user-attachments/assets/09633d15-43b8-4660-bc0c-81f9394dc271)

## websocket通信原理和机制

WebSocket是一种网络传输协议，可在单个TCP连接上进行全双工通信，位于OSI模型的应用层。**浏览器和服务器只需要完成一次握手，两者之间就可以建立持久性的连接，并进行双向数据传输**。

WebSocket的主要特点是：
- 使用HTTP协议进行握手：WebSocket使用HTTP协议进行握手，客户端向服务器发送一个Upgrade请求，服务器返回一个101 Switching Protocols响应，表示同意建立WebSocket连接。
- 使用TCP协议进行传输：WebSocket使用TCP协议进行传输，客户端和服务器之间的连接是双向的，可以互相发送和接收数据。
- 使用帧格式进行编码：WebSocket使用帧格式进行编码，每个数据包由一个或多个帧组成，每个帧包含一个头部和一个负载。头部包含了帧的类型、长度、掩码等信息，负载包含了实际的数据。
- 支持文本和二进制数据：WebSocket支持文本和二进制数据，可以根据不同的场景选择不同的数据类型。

![image](https://github.com/user-attachments/assets/edea412f-cbce-4890-b85b-285081f93360)

