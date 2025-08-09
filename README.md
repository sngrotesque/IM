# IM
此仓库保留各种IM的（C++）实现，主要代码均为AI生成（不保证代码的正确性和可维护性）。

### 使用了以下AI
1. [Deepseek（深度求索）](https://yuanbao.tencent.com/)
2. [Doubao（豆包）](https://www.doubao.com/)
3. [Copilot](https://copilot.microsoft.com/)
4. [Kimi](https://www.kimi.com/)
5. [DeepAi](https://deepai.org/chat)
6. [YiYan（文心一言）](https://yiyan.baidu.com/)
7. [TongYi（通义）](https://www.tongyi.com/)

---

请使用C++按照下面的要求实现服务端和客户端代码。

1. 如果需要使用容器，只允许使用std::vector和std::string。
2. Windows平台。
3. 使用select函数以及它的api来实现socket多路复用。
4. 这是一个TCP服务端，必须允许多个客户端的同时连接和消息发送。
5. 超时时间为30秒，如果在无连接的情况下，将直接关闭程序。
6. 不能使用任何除了多路复用以外的并发技术（如多线程、多进程、异步，协程等）。
7. 服务端需记录每个客户端的用户名。
8. 服务端收到来自客户端的消息时，必须显示此条消息所对应的客户端的IP地址和端口信息和用户名。
9. 服务端与客户端均为小端序传输，不需要转换大端序。
10. 如果所有客户端断开连接，服务端关闭。
11. 任何一个客户端发了消息之后需广播给所有已连接的客户端（客户端之间可以看到其他用户发送的消息）。
12. 客户端发送的消息应带有UNIX时间戳（格式为Python中的time.time()那样的格式，包括秒级和微秒级）。
13. 客户端发送的消息将为下面的结构，首先是4个字节，这是一个uint32_t数，代表了接下来的消息的长度。比如说客户端要发送一个"hello"，那么消息包将为（hex）`0500000068656c6c6f`。  
    服务端在解析这个包的时候，需要先接收4字节的长度，然后按照长度完整接收客户端消息，然后以"Client [Username] [IP_Addrees:Port] [Timestamp]: Message"这样的格式展示。  
    任意用户在看到其他用户发送的消息时展示的格式应为"Client [Username] [Timestamp]: Message"格式。
14. 添加用户登录功能（使用密码登录），对于服务端密码库（如哈希）请使用OpenSSL库的EVP接口。
15. （针对第14条的补充）不允许使用任何一种数据库（包括NoSQL，MySql，pgsql等），允许使用[protobuf](https://protobuf.dev)或[yaml](https://yaml.org/)或[xml](https://www.w3schools.com/xml/xml_whatis.asp)或[json](https://en.wikipedia.org/wiki/JSON)。
