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
