### 简介与协议

下面给出一套在 Windows 平台使用 C++ 与 select 实现的多人 TCP 聊天示例（服务端与客户端）。满足你提出的约束条件：

- 仅使用 std::vector 与 std::string 作为容器。
- 使用 select 做多路复用，不使用线程、进程、协程或其他并发技术。
- 服务端可同时接入多个客户端，记录用户名并广播消息。
- 超时 30 秒：若无任何客户端连接且超时，服务端直接退出；若所有客户端断开，服务端立即退出。
- 传输小端序；应用层消息帧格式：
  - 先发 4 字节（uint32_t，小端）表示后续载荷长度 N；
  - 后接 N 字节 UTF-8 文本载荷。
- 客户端消息需包含 UNIX 时间戳（形如 Python time.time() 的浮点秒带微秒）。
- 登录与密码校验：服务端使用 OpenSSL EVP（PBKDF2-HMAC-SHA256）验证口令。用户库用 JSON 文件存储（无数据库）。
- 服务端打印收到消息：Client [Username] [IP:Port] [Timestamp]: Message
- 客户端看到广播：Client [Username] [Timestamp]: Message
- 协议载荷（文本）两种类型：
  - 登录：LOGIN <username> <password>
  - 发送消息：MSG <timestamp> <text>

### 服务端代码（server.cpp）
[server.cc](https://github.com/sngrotesque/IM/blob/master/AI_Copilot/server.cc)

### 客户端代码（client.cpp）
[client.cc](https://github.com/sngrotesque/IM/blob/master/AI_Copilot/client.cc)

说明：
- 仍然使用 4 字节小端长度 + 文本载荷帧。
- 首先发送登录帧：LOGIN <username> <password>，等待服务端返回 OK/ERR。
- 之后进入主循环：
  - 使用 select 监听 socket 的可读事件接收广播。
  - 同时用 Windows 控制台非阻塞方法采集用户输入（不使用线程）：使用 PeekConsoleInput 构造行缓冲。回车后发送一条消息帧 MSG <timestamp> <text>。
- 时间戳生成：std::chrono 获取微秒级，再格式化为 “秒.微秒(6位)” 字符串。

---

### users.json 示例与口令策略

- 首次启动服务端若未找到 users.json，会自动生成一个用户：
  - username: test
  - password: password123
  - iterations: 100000
  - salt/hash: 随机生成（PBKDF2-HMAC-SHA256，32 字节）
- users.json 结构大致如下（示例）：
```json
[
  {
    "username": "test",
    "salt": "8f2a8c...16字节盐的hex...",
    "hash": "a1b2c3...32字节派生key的hex...",
    "iterations": 100000
  }
]
```
- 要添加新用户，可手动编辑 JSON 并重启服务端，但需要使用相同的 PBKDF2 参数和 hex 编码。可临时在 server.cpp 中添加一个生成入口，或另写一个小工具。

---

### 编译与运行（Windows/MSVC）

- 先安装 OpenSSL 并确保 libcrypto 可被链接（库名可能为 libcrypto.lib 或 libcrypto-3-x64.lib，按你的安装环境调整）。
- 编译：
  - cl /std:c++17 server.cpp /link Ws2_32.lib libcrypto.lib
  - cl /std:c++17 client.cpp /link Ws2_32.lib
- 运行：
  - 启动服务端：server.exe 5555
  - 启动客户端：client.exe 127.0.0.1 5555
  - 客户端登录：Username: test，Password: password123
  - 输入消息回车发送；输入 /quit 退出客户端。

---

### 关键行为与约束落实

- 多路复用：仅使用 select 管理监听 socket 与已连接客户端 socket（服务端），客户端用 select 处理 socket，同时用非阻塞控制台 API 轮询输入。
- 超时与退出：
  - 服务端 select 30 秒超时：若期间未有任何客户端连接且超时，即退出。
  - 所有客户端断开时，服务端立即退出。
- 小端序传输：长度字段用小端序写入与读取；不做网络字节序转换（仅 socket 端口显示使用 ntohs 与 inet_ntop，与应用层传输要求不冲突）。
- 登录与广播：
  - 登录成功后才允许 MSG。
  - 任意客户端发送的消息，服务端广播给所有已认证在线客户端。
- 时间戳：
  - 客户端负责编入 “秒.微秒(6位)” 格式的 UNIX 时间戳；服务端按其字符串显示与广播。

---

### 已知注意点与可扩展建议

- 本示例为教学/演示用途，未实现发送队列与拥塞控制；在极端情况下 send 可能阻塞或失败。如需健壮性，建议：
  - 为每个客户端维护发送缓冲，并在 select 的写集合中按可写再发送。
- 客户端控制台输入简化为基本 ASCII。若需完整 UTF-8，需做宽/多字节转换。
- 协议为明文，未加密传输。生产场景建议使用 TLS（例如 Schannel 或 OpenSSL SSL/TLS）保护口令与数据。
- JSON 解析为极简定制，仅适配 users.json 的固定结构；若需复杂管理，可引入更健壮的解析（在不引入额外容器前提下也可手写有限状态机解析器）。
- 口令传输为明文；服务端使用 PBKDF2 验证存储口令哈希，存储安全性较好，但传输链路仍需 TLS 才可抵御窃听。
