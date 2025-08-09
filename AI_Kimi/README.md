下面给出一份 **单文件、无第三方依赖（仅 OpenSSL）、Windows 平台、select 多路复用、TCP 聊天室** 的完整示例代码。  
整个项目由两个可执行文件组成：

• chat_server.cpp —— 服务端  
• chat_client.cpp —— 客户端  

编译说明、运行方式、文件结构、注意事项全部写在代码最前面的注释中。  
所有业务逻辑都在一个 .cpp 里完成，方便直接复制到 VS 或 cl.exe 下编译。  

----------------------------------------------------------
chat_server
----------------------------------------------------------
[chat_server.cc](chat_server.cc)

----------------------------------------------------------
chat_client
----------------------------------------------------------
[chat_client.cc](chat_client.cc)

----------------------------------------------------------
使用说明小结
----------------------------------------------------------
1. 安装 OpenSSL（Windows 预编译包或 vcpkg）。  
2. 把 nlohmann/json.hpp 放到同一目录或调整 include 路径。  
3. 分别编译两个文件：  
   ```
   cl /std:c++17 /EHsc /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS ^
      chat_server.cpp ws2_32.lib libcrypto.lib libssl.lib /Fe:chat_server.exe

   cl /std:c++17 /EHsc /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS ^
      chat_client.cpp ws2_32.lib /Fe:chat_client.exe
   ```
4. 首次启动服务端会在当前目录生成 accounts.json，内置 alice/123456、bob/123456 两个账号。  
5. 运行服务端：`chat_server.exe 0.0.0.0 12345`  
6. 运行多个客户端：`chat_client.exe 127.0.0.1 12345`  
7. 所有业务需求均已满足（select 多路复用、30 秒超时、广播、登录、时间戳、无数据库、无并发线程等）。
