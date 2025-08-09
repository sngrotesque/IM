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

---

### 服务端代码（server.cpp）

```cpp
// server.cpp
// Build: cl /std:c++17 server.cpp /link Ws2_32.lib libcrypto.lib
// Note: link OpenSSL libcrypto as available on your system.

// Windows & Sockets
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")

// OpenSSL
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#pragma comment(lib, "libcrypto.lib")

// C/C++
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <io.h>

struct UserRecord {
    std::string username;
    std::string saltHex;
    std::string hashHex;
    int iterations;
};

// 简单 hex 编解码
static std::string toHex(const unsigned char* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        unsigned char b = data[i];
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0F]);
    }
    return out;
}
static std::vector<unsigned char> fromHex(const std::string& s) {
    std::vector<unsigned char> out;
    if (s.size() % 2 != 0) return out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        auto hexVal = [](char c)->int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hexVal(s[i]);
        int lo = hexVal(s[i+1]);
        if (hi < 0 || lo < 0) return std::vector<unsigned char>();
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out;
}

// 生成 PBKDF2-HMAC-SHA256
static bool pbkdf2_sha256(const std::string& password,
                          const std::vector<unsigned char>& salt,
                          int iterations,
                          std::vector<unsigned char>& outKey, size_t keyLen = 32) {
    outKey.resize(keyLen);
    const EVP_MD* md = EVP_sha256();
    int rc = PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                               salt.data(), static_cast<int>(salt.size()),
                               iterations, md, static_cast<int>(keyLen), outKey.data());
    return rc == 1;
}

// 简易 JSON 读取（针对本程序固定结构）：users.json
// 格式: [{"username":"alice","salt":"...","hash":"...","iterations":100000}, ...]
static std::string readFile(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) return "";
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    std::string s;
    s.resize(n);
    if (n > 0) fread(&s[0], 1, n, fp);
    fclose(fp);
    return s;
}
static bool writeFile(const std::string& path, const std::string& data) {
    FILE* fp = fopen(path.c_str(), "wb");
    if (!fp) return false;
    fwrite(data.data(), 1, data.size(), fp);
    fclose(fp);
    return true;
}
static std::string escapeJson(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '\\' || c == '\"') { o.push_back('\\'); o.push_back(c); }
        else if (c == '\n') { o += "\\n"; }
        else o.push_back(c);
    }
    return o;
}

// 极简查找 "key":"value" 或 "key":number
static bool extractJsonString(const std::string& obj, const std::string& key, std::string& out) {
    std::string pat = "\"" + key + "\"";
    size_t p = obj.find(pat);
    if (p == std::string::npos) return false;
    p = obj.find(':', p);
    if (p == std::string::npos) return false;
    p = obj.find('\"', p);
    if (p == std::string::npos) return false;
    size_t q = obj.find('\"', p + 1);
    if (q == std::string::npos) return false;
    out = obj.substr(p + 1, q - (p + 1));
    return true;
}
static bool extractJsonInt(const std::string& obj, const std::string& key, int& out) {
    std::string pat = "\"" + key + "\"";
    size_t p = obj.find(pat);
    if (p == std::string::npos) return false;
    p = obj.find(':', p);
    if (p == std::string::npos) return false;
    size_t q = p + 1;
    while (q < obj.size() && (obj[q] == ' ' || obj[q] == '\t')) q++;
    size_t r = q;
    while (r < obj.size() && (obj[r] == '-' || (obj[r] >= '0' && obj[r] <= '9'))) r++;
    try {
        out = std::stoi(obj.substr(q, r - q));
    } catch (...) { return false; }
    return true;
}

// 解析 users.json
static std::vector<UserRecord> loadUsers(const std::string& path) {
    std::vector<UserRecord> users;
    std::string s = readFile(path);
    if (s.empty()) return users;
    // 逐个对象粗略切分
    size_t i = 0;
    while (true) {
        size_t l = s.find('{', i);
        if (l == std::string::npos) break;
        size_t r = s.find('}', l);
        if (r == std::string::npos) break;
        std::string obj = s.substr(l, r - l + 1);
        UserRecord u;
        if (extractJsonString(obj, "username", u.username) &&
            extractJsonString(obj, "salt", u.saltHex) &&
            extractJsonString(obj, "hash", u.hashHex) &&
            extractJsonInt(obj, "iterations", u.iterations)) {
            users.push_back(u);
        }
        i = r + 1;
    }
    return users;
}

static std::string usersToJson(const std::vector<UserRecord>& users) {
    std::string out = "[\n";
    for (size_t i = 0; i < users.size(); ++i) {
        const auto& u = users[i];
        out += "  {\"username\":\"" + escapeJson(u.username) + "\","
               "\"salt\":\"" + u.saltHex + "\","
               "\"hash\":\"" + u.hashHex + "\","
               "\"iterations\":" + std::to_string(u.iterations) + "}";
        if (i + 1 < users.size()) out += ",";
        out += "\n";
    }
    out += "]\n";
    return out;
}

static bool findUser(const std::vector<UserRecord>& users, const std::string& name, UserRecord& out) {
    for (const auto& u : users) if (u.username == name) { out = u; return true; }
    return false;
}

static std::string nowTimeStr() {
    // 仅用于日志（服务器本地时间可选）
    char buf[64];
    std::time_t t = std::time(nullptr);
    std::tm tmv;
    localtime_s(&tmv, &t);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return std::string(buf);
}

struct Client {
    SOCKET sock = INVALID_SOCKET;
    std::string ipPort;
    std::string username;
    bool authed = false;
    std::vector<char> inbuf; // 累积接收缓冲
    bool alive = true;
};

static void closesock(SOCKET s) {
    if (s != INVALID_SOCKET) {
        closesocket(s);
    }
}

// 小端写入长度 + 发送完整缓冲
static bool sendFrame(SOCKET s, const std::string& payload) {
    uint32_t n = static_cast<uint32_t>(payload.size());
    unsigned char hdr[4];
    hdr[0] = (unsigned char)((n) & 0xFF);
    hdr[1] = (unsigned char)((n >> 8) & 0xFF);
    hdr[2] = (unsigned char)((n >> 16) & 0xFF);
    hdr[3] = (unsigned char)((n >> 24) & 0xFF);
    // 发送头
    const char* p = (const char*)hdr;
    int toSend = 4;
    while (toSend > 0) {
        int m = send(s, p, toSend, 0);
        if (m <= 0) return false;
        p += m; toSend -= m;
    }
    // 发送体
    const char* q = payload.data();
    int left = (int)payload.size();
    while (left > 0) {
        int m = send(s, q, left, 0);
        if (m <= 0) return false;
        q += m; left -= m;
    }
    return true;
}

static void broadcast(std::vector<Client>& clients, const std::string& line) {
    // line 已经是显示用的 "Client [Username] [Timestamp]: Message"
    for (auto& c : clients) {
        if (!c.alive || !c.authed) continue;
        if (!sendFrame(c.sock, line)) {
            c.alive = false;
        }
    }
}

// 从 inbuf 中按帧提取一条载荷（若不足返回空字符串）
static std::string tryPopFrame(std::vector<char>& buf) {
    if (buf.size() < 4) return "";
    uint32_t n = (uint8_t)buf[0] | ((uint32_t)(uint8_t)buf[1] << 8) |
                 ((uint32_t)(uint8_t)buf[2] << 16) | ((uint32_t)(uint8_t)buf[3] << 24);
    if (buf.size() < 4u + n) return "";
    std::string payload;
    if (n > 0) payload.assign(&buf[4], &buf[4 + n]);
    buf.erase(buf.begin(), buf.begin() + 4 + n);
    return payload;
}

static std::string formatClientAddr(const sockaddr_in& sa) {
    char ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, (void*)&sa.sin_addr, ip, sizeof(ip));
    unsigned short port = ntohs(sa.sin_port);
    char out[64];
    sprintf_s(out, "%s:%hu", ip, port);
    return std::string(out);
}

int main(int argc, char** argv) {
    // 参数
    int port = 5555;
    if (argc >= 2) port = std::atoi(argv[1]);

    // 初始化 WinSock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // 初始化 OpenSSL（EVP 不需特别 init，确保链接库）
    // 加载用户库
    const std::string usersPath = "users.json";
    std::vector<UserRecord> users = loadUsers(usersPath);
    if (users.empty()) {
        // 若不存在则创建一个示例用户：username=test, password=password123
        UserRecord u;
        u.username = "test";
        u.iterations = 100000;
        unsigned char salt[16];
        RAND_bytes(salt, sizeof(salt));
        u.saltHex = toHex(salt, sizeof(salt));
        std::vector<unsigned char> key;
        pbkdf2_sha256("password123", std::vector<unsigned char>(salt, salt + sizeof(salt)), u.iterations, key, 32);
        u.hashHex = toHex(key.data(), key.size());
        users.push_back(u);
        writeFile(usersPath, usersToJson(users));
        printf("Created users.json with a sample user: test / password123\n");
    }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        printf("socket() failed\n");
        WSACleanup();
        return 1;
    }
    u_long nb = 1;
    ioctlsocket(listenSock, FIONBIO, &nb);

    int on = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((u_short)port);

    if (bind(listenSock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        printf("bind() failed\n");
        closesock(listenSock);
        WSACleanup();
        return 1;
    }
    if (listen(listenSock, SOMAXCONN) != 0) {
        printf("listen() failed\n");
        closesock(listenSock);
        WSACleanup();
        return 1;
    }

    printf("[%s] Server listening on port %d ...\n", nowTimeStr().c_str(), port);

    std::vector<Client> clients;
    bool running = true;
    bool everHadClient = false;

    while (running) {
        // 若所有客户端断开，直接关闭
        size_t aliveCount = 0;
        for (auto& c : clients) if (c.alive) aliveCount++;
        if (aliveCount == 0 && everHadClient) {
            printf("[%s] All clients disconnected. Shutting down.\n", nowTimeStr().c_str());
            break;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listenSock, &rfds);
        SOCKET maxfd = listenSock;

        for (auto& c : clients) {
            if (!c.alive) continue;
            FD_SET(c.sock, &rfds);
            if (c.sock > maxfd) maxfd = c.sock;
        }

        timeval tv{};
        tv.tv_sec = 30;
        tv.tv_usec = 0;

        int nready = select((int)maxfd + 1, &rfds, nullptr, nullptr, &tv);
        if (nready < 0) {
            printf("select() error, shutting down.\n");
            break;
        } else if (nready == 0) {
            // 超时：若无任何连接，直接关闭
            if (!everHadClient) {
                printf("[%s] No connections within 30s. Shutting down.\n", nowTimeStr().c_str());
                break;
            }
            // 有连接时允许继续
            continue;
        }

        // 新连接
        if (FD_ISSET(listenSock, &rfds)) {
            sockaddr_in cliaddr{};
            int clen = sizeof(cliaddr);
            SOCKET cs = accept(listenSock, (sockaddr*)&cliaddr, &clen);
            if (cs != INVALID_SOCKET) {
                u_long nb2 = 1;
                ioctlsocket(cs, FIONBIO, &nb2);
                Client c;
                c.sock = cs;
                c.ipPort = formatClientAddr(cliaddr);
                c.authed = false;
                c.alive = true;
                clients.push_back(c);
                everHadClient = true;
                printf("[%s] New connection: %s\n", nowTimeStr().c_str(), c.ipPort.c_str());
            }
        }

        // 收数据
        for (auto& c : clients) {
            if (!c.alive) continue;
            if (!FD_ISSET(c.sock, &rfds)) continue;

            char buf[4096];
            int m = recv(c.sock, buf, sizeof(buf), 0);
            if (m <= 0) {
                printf("[%s] Disconnected: %s\n", nowTimeStr().c_str(), c.ipPort.c_str());
                c.alive = false;
                closesock(c.sock);
                continue;
            }
            c.inbuf.insert(c.inbuf.end(), buf, buf + m);

            while (true) {
                std::string payload = tryPopFrame(c.inbuf);
                if (payload.empty()) break;

                // 处理载荷
                if (!c.authed) {
                    // 期待: LOGIN <username> <password>
                    const std::string prefix = "LOGIN ";
                    if (payload.rfind(prefix, 0) != 0) {
                        sendFrame(c.sock, "ERR Invalid login command");
                        continue;
                    }
                    // 拆分
                    size_t p1 = payload.find(' ', 6);
                    if (p1 == std::string::npos) {
                        sendFrame(c.sock, "ERR Invalid login format");
                        continue;
                    }
                    std::string uname = payload.substr(6, p1 - 6);
                    std::string pwd = payload.substr(p1 + 1);

                    UserRecord ur;
                    if (!findUser(users, uname, ur)) {
                        sendFrame(c.sock, "ERR Unknown user");
                        continue;
                    }
                    auto salt = fromHex(ur.saltHex);
                    auto want = fromHex(ur.hashHex);
                    std::vector<unsigned char> got;
                    if (!pbkdf2_sha256(pwd, salt, ur.iterations, got, want.size())) {
                        sendFrame(c.sock, "ERR Auth failure");
                        continue;
                    }
                    if (got != want) {
                        sendFrame(c.sock, "ERR Auth failure");
                        continue;
                    }
                    c.authed = true;
                    c.username = uname;
                    sendFrame(c.sock, "OK");
                    printf("[%s] Auth success: %s as %s\n", nowTimeStr().c_str(), c.ipPort.c_str(), c.username.c_str());
                } else {
                    // 期待: MSG <timestamp> <text>
                    const std::string prefix = "MSG ";
                    if (payload.rfind(prefix, 0) != 0) {
                        sendFrame(c.sock, "ERR Invalid message");
                        continue;
                    }
                    size_t p1 = payload.find(' ', 4);
                    if (p1 == std::string::npos) {
                        sendFrame(c.sock, "ERR Invalid message format");
                        continue;
                    }
                    std::string ts = payload.substr(4, p1 - 4);
                    std::string text = payload.substr(p1 + 1);

                    // 服务端显示：带 IP:Port
                    std::string serverLine = "Client [" + c.username + "] [" + c.ipPort + "] [" + ts + "]: " + text;
                    printf("%s\n", serverLine.c_str());

                    // 广播：不带 IP:Port
                    std::string clientLine = "Client [" + c.username + "] [" + ts + "]: " + text;
                    broadcast(clients, clientLine);
                }
            }
        }

        // 清理失活客户端
        {
            std::vector<Client> nc;
            nc.reserve(clients.size());
            for (auto& c : clients) if (c.alive) nc.push_back(c);
            clients.swap(nc);
        }
    }

    for (auto& c : clients) if (c.sock != INVALID_SOCKET) closesock(c.sock);
    closesock(listenSock);
    WSACleanup();
    return 0;
}
```

---

### 客户端代码（client.cpp）

说明：
- 仍然使用 4 字节小端长度 + 文本载荷帧。
- 首先发送登录帧：LOGIN <username> <password>，等待服务端返回 OK/ERR。
- 之后进入主循环：
  - 使用 select 监听 socket 的可读事件接收广播。
  - 同时用 Windows 控制台非阻塞方法采集用户输入（不使用线程）：使用 PeekConsoleInput 构造行缓冲。回车后发送一条消息帧 MSG <timestamp> <text>。
- 时间戳生成：std::chrono 获取微秒级，再格式化为 “秒.微秒(6位)” 字符串。

```cpp
// client.cpp
// Build: cl /std:c++17 client.cpp /link Ws2_32.lib

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>

// 简易读取密码（关闭回显）
static std::string readPassword(const char* prompt) {
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldMode = 0;
    GetConsoleMode(hIn, &oldMode);
    DWORD newMode = oldMode & ~ENABLE_ECHO_INPUT;
    SetConsoleMode(hIn, newMode);

    printf("%s", prompt);
    std::string pwd;
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin)) {
        // 去掉尾部换行
        size_t n = strlen(buf);
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) n--;
        pwd.assign(buf, buf + n);
    }
    printf("\n");
    SetConsoleMode(hIn, oldMode);
    return pwd;
}

// 控制台非阻塞行读取：使用 PeekConsoleInput 收集键盘事件
static bool pollConsoleLine(std::string& lineBuf, std::string& outLine) {
    outLine.clear();
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD nEvents = 0;
    if (!GetNumberOfConsoleInputEvents(hIn, &nEvents) || nEvents == 0) return false;

    std::vector<INPUT_RECORD> recs;
    recs.resize(nEvents);
    DWORD nRead = 0;
    if (!PeekConsoleInput(hIn, recs.data(), nEvents, &nRead) || nRead == 0) return false;

    // 仅在有键盘事件时 ReadConsoleInput 真正取走
    bool hasKey = false;
    for (DWORD i = 0; i < nRead; ++i) {
        if (recs[i].EventType == KEY_EVENT && recs[i].Event.KeyEvent.bKeyDown) { hasKey = true; break; }
    }
    if (!hasKey) return false;

    // 读取并处理
    std::vector<INPUT_RECORD> recs2(nRead);
    DWORD nRead2 = 0;
    if (!ReadConsoleInput(hIn, recs2.data(), nRead, &nRead2)) return false;

    for (DWORD i = 0; i < nRead2; ++i) {
        if (recs2[i].EventType != KEY_EVENT) continue;
        KEY_EVENT_RECORD& kev = recs2[i].Event.KeyEvent;
        if (!kev.bKeyDown) continue;
        WCHAR wc = kev.uChar.UnicodeChar;
        if (wc == 0) continue;
        if (wc == L'\r') {
            // 回车 -> 产生一行
            outLine = lineBuf;
            lineBuf.clear();
            return !outLine.empty();
        } else if (wc == L'\b') {
            if (!lineBuf.empty()) lineBuf.pop_back();
        } else if (wc == L'\n') {
            // ignore
        } else {
            // 简化：仅处理基础 BMP 字符作为单字节（若需要 UTF-8 可做转换）
            char c = (char)(wc & 0xFF);
            lineBuf.push_back(c);
        }
    }
    return false;
}

static bool sendFrame(SOCKET s, const std::string& payload) {
    uint32_t n = (uint32_t)payload.size();
    unsigned char hdr[4] = {
        (unsigned char)(n & 0xFF),
        (unsigned char)((n >> 8) & 0xFF),
        (unsigned char)((n >> 16) & 0xFF),
        (unsigned char)((n >> 24) & 0xFF)
    };
    const char* p = (const char*)hdr;
    int toSend = 4;
    while (toSend > 0) {
        int m = send(s, p, toSend, 0);
        if (m <= 0) return false;
        p += m; toSend -= m;
    }
    const char* q = payload.data();
    int left = (int)payload.size();
    while (left > 0) {
        int m = send(s, q, left, 0);
        if (m <= 0) return false;
        q += m; left -= m;
    }
    return true;
}

static std::string tryPopFrame(std::vector<char>& buf) {
    if (buf.size() < 4) return "";
    uint32_t n = (uint8_t)buf[0] | ((uint32_t)(uint8_t)buf[1] << 8) |
                 ((uint32_t)(uint8_t)buf[2] << 16) | ((uint32_t)(uint8_t)buf[3] << 24);
    if (buf.size() < 4u + n) return "";
    std::string payload;
    if (n > 0) payload.assign(&buf[4], &buf[4 + n]);
    buf.erase(buf.begin(), buf.begin() + 4 + n);
    return payload;
}

static std::string nowTimestampFloat() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto us = time_point_cast<microseconds>(now).time_since_epoch().count();
    long long sec = us / 1000000;
    long long micro = us % 1000000;
    char buf[64];
    // 格式：秒.微秒（6位前导零）
    sprintf_s(buf, "%lld.%06lld", sec, micro);
    return std::string(buf);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: client.exe <server_ip> <port>\n");
        return 0;
    }
    const char* serverIp = argv[1];
    int port = std::atoi(argv[2]);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        printf("socket() failed\n");
        WSACleanup();
        return 1;
    }

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u_short)port);
    inet_pton(AF_INET, serverIp, &sa.sin_addr);

    if (connect(s, (sockaddr*)&sa, sizeof(sa)) != 0) {
        printf("connect() failed\n");
        closesocket(s);
        WSACleanup();
        return 1;
    }
    printf("Connected to %s:%d\n", serverIp, port);

    // 登录
    std::string username;
    printf("Username: ");
    {
        char buf[256];
        if (!fgets(buf, sizeof(buf), stdin)) { printf("Input error\n"); return 1; }
        size_t n = strlen(buf);
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) n--;
        username.assign(buf, buf + n);
    }
    std::string password = readPassword("Password: ");

    std::string loginPayload = "LOGIN " + username + " " + password;
    if (!sendFrame(s, loginPayload)) {
        printf("Failed to send LOGIN\n");
        closesocket(s); WSACleanup(); return 1;
    }

    // 等待 OK/ERR（简化：阻塞等待一帧）
    std::vector<char> inbuf;
    while (true) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        timeval tv{10, 0}; // 10s 等待登录响应
        int r = select((int)s + 1, &rfds, nullptr, nullptr, &tv);
        if (r <= 0) { printf("Login timeout/error\n"); closesocket(s); WSACleanup(); return 1; }
        if (FD_ISSET(s, &rfds)) {
            char tmp[2048];
            int m = recv(s, tmp, sizeof(tmp), 0);
            if (m <= 0) { printf("Server closed\n"); closesocket(s); WSACleanup(); return 1; }
            inbuf.insert(inbuf.end(), tmp, tmp + m);
            std::string resp = tryPopFrame(inbuf);
            if (!resp.empty()) {
                if (resp == "OK") {
                    printf("Login success. You can type messages now. Press Enter to send.\n");
                    break;
                } else {
                    printf("Login failed: %s\n", resp.c_str());
                    closesocket(s); WSACleanup(); return 1;
                }
            }
        }
    }

    // 主循环：select 处理 socket；非阻塞收集控制台输入
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);

    std::string lineBuf;
    while (true) {
        // 先非阻塞读控制台（若完成一整行则发送）
        std::string outLine;
        if (pollConsoleLine(lineBuf, outLine)) {
            if (outLine == "/quit") {
                printf("Bye.\n"); break;
            }
            std::string ts = nowTimestampFloat();
            std::string payload = "MSG " + ts + " " + outLine;
            if (!sendFrame(s, payload)) {
                printf("Send failed. Exiting.\n"); break;
            }
        }

        // select 等待 socket 可读（短超时，避免阻塞输入轮询）
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        timeval tv{0, 200 * 1000}; // 200ms
        int r = select((int)s + 1, &rfds, nullptr, nullptr, &tv);
        if (r < 0) {
            printf("select() error\n"); break;
        } else if (r == 0) {
            continue; // 继续轮询输入
        }
        if (FD_ISSET(s, &rfds)) {
            char tmp[4096];
            int m = recv(s, tmp, sizeof(tmp), 0);
            if (m == 0) { printf("Server closed.\n"); break; }
            if (m < 0) {
                int e = WSAGetLastError();
                if (e == WSAEWOULDBLOCK) continue;
                printf("recv error\n"); break;
            }
            inbuf.insert(inbuf.end(), tmp, tmp + m);
            while (true) {
                std::string msg = tryPopFrame(inbuf);
                if (msg.empty()) break;
                // 直接打印已格式化字符串：Client [Username] [Timestamp]: Message
                printf("%s\n", msg.c_str());
            }
        }
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
```

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
