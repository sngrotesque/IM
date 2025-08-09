/****************************************************************************************
 *  Chat Server
 *  Windows / C++17 / select multiplexing / TCP / OpenSSL EVP
 *
 *  编译（VS2019+ 或 cl.exe）：
 *      cl /std:c++17 /EHsc /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS ^
 *         chat_server.cpp ws2_32.lib libcrypto.lib libssl.lib /Fe:chat_server.exe
 *
 *  运行：
 *      chat_server.exe 0.0.0.0 12345
 *
 *  账号文件：accounts.json  （首次启动若不存在则自动创建演示账号）
 *  账号格式：{"alice":"$5$rounds=1000$salt123...","bob":"..."}
 ****************************************************************************************/
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <nlohmann/json.hpp>   // 单文件 json.hpp 可从 https://github.com/nlohmann/json 下载

#pragma comment(lib,"ws2_32.lib")

using json = nlohmann::json;

const int MAX_BUF      = 4096;
const int SELECT_TO_MS = 30 * 1000;          // 30 秒无连接则退出
const int LISTEN_BACKLOG = 64;

struct Client {
    SOCKET      sock;
    std::string ip;
    uint16_t    port;
    std::string username;
    std::string recvBuf;          // 未处理完的原始数据
};

std::unordered_map<SOCKET, Client> g_clients;
SOCKET g_listenSock = INVALID_SOCKET;

/* ----------------------------- 工具函数 --------------------------------- */
std::string timestampStr() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms  = duration_cast<microseconds>(now.time_since_epoch()).count();
    return std::to_string(ms / 1000000) + "." + std::to_string(ms % 1000000);
}

void die(const char* msg) {
    std::cerr << msg << "  (" << WSAGetLastError() << ")\n";
    WSACleanup();
    exit(1);
}

/* ----------------------------- 密码相关 --------------------------------- */
std::string hashPassword(const std::string& plain) {
    const char* saltPrefix = "$5$rounds=1000$";   // SHA256-crypt
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));
    char saltStr[32];
    for (size_t i = 0; i < sizeof(salt); ++i)
        sprintf(saltStr + i * 2, "%02x", salt[i]);
    std::string saltFull = std::string(saltPrefix) + saltStr;
    char* out = EVP_PKEY_new_raw_private_key(0, NULL, NULL);  // 占位
    out = crypt(plain.c_str(), saltFull.c_str());             // POSIX crypt 在 Windows 需用 openssl crypt
    if (!out) return "";
    std::string ret(out);
    OPENSSL_free(out);
    return ret;
}

bool verifyPassword(const std::string& plain, const std::string& stored) {
    char* out = crypt(plain.c_str(), stored.c_str());
    if (!out) return false;
    bool ok = (stored == out);
    OPENSSL_free(out);
    return ok;
}

/* ----------------------------- 账号文件 --------------------------------- */
json g_accounts;

void loadAccounts() {
    std::ifstream f("accounts.json");
    if (!f.is_open()) {
        // 创建演示账号
        g_accounts["alice"] = hashPassword("123456");
        g_accounts["bob"]   = hashPassword("123456");
        std::ofstream o("accounts.json");
        o << g_accounts.dump(4);
    } else {
        f >> g_accounts;
    }
}

bool authUser(const std::string& user, const std::string& pwd) {
    auto it = g_accounts.find(user);
    if (it == g_accounts.end()) return false;
    return verifyPassword(pwd, it.value());
}

/* ----------------------------- 网络相关 --------------------------------- */
void closeClient(SOCKET s) {
    closesocket(s);
    g_clients.erase(s);
    std::cout << "Client disconnected. Total clients: " << g_clients.size() << "\n";
}

bool sendAll(SOCKET s, const std::string& data) {
    uint32_t len = (uint32_t)data.size();
    std::string pkt((char*)&len, 4);
    pkt += data;
    size_t total = 0;
    while (total < pkt.size()) {
        int n = send(s, pkt.data() + total, (int)(pkt.size() - total), 0);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

/* 处理登录逻辑：返回 true 表示成功登录 */
bool handleLogin(Client& c, const std::string& payload) {
    // payload 格式： user\npass
    size_t pos = payload.find('\n');
    if (pos == std::string::npos) return false;
    std::string user = payload.substr(0, pos);
    std::string pass = payload.substr(pos + 1);
    if (authUser(user, pass)) {
        c.username = user;
        return true;
    }
    return false;
}

void broadcast(const std::string& msg) {
    for (auto& [s, cli] : g_clients) {
        sendAll(s, msg);
    }
}

void processClient(Client& c) {
    while (c.recvBuf.size() >= 4) {
        uint32_t len = *(uint32_t*)c.recvBuf.data();
        if (c.recvBuf.size() < 4 + len) return;   // 还没收完
        std::string payload = c.recvBuf.substr(4, len);
        c.recvBuf.erase(0, 4 + len);

        if (c.username.empty()) {
            // 登录阶段
            if (handleLogin(c, payload)) {
                std::string welcome = "Welcome, " + c.username + "!";
                sendAll(c.sock, welcome);
                std::cout << "User " << c.username << " logged in from "
                          << c.ip << ":" << c.port << "\n";
            } else {
                sendAll(c.sock, "Login failed.");
                closesocket(c.sock);
                g_clients.erase(c.sock);
                return;
            }
        } else {
            // 聊天阶段
            std::string ts = timestampStr();
            std::string displayServer = "Client [" + c.username + "] [" +
                                        c.ip + ":" + std::to_string(c.port) +
                                        "] [" + ts + "]: " + payload;
            std::string displayClient = "Client [" + c.username + "] [" +
                                        ts + "]: " + payload;
            std::cout << displayServer << "\n";
            broadcast(displayClient);
        }
    }
}

/* ----------------------------- 主函数 --------------------------------- */
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: chat_server.exe <ip> <port>\n";
        return 1;
    }
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) die("WSAStartup failed");

    loadAccounts();

    g_listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listenSock == INVALID_SOCKET) die("socket failed");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(std::stoi(argv[2]));
    inet_pton(AF_INET, argv[1], &addr.sin_addr);

    if (bind(g_listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
        die("bind failed");
    if (listen(g_listenSock, LISTEN_BACKLOG) == SOCKET_ERROR)
        die("listen failed");

    std::cout << "Server started at " << argv[1] << ":" << argv[2] << "\n";

    fd_set master, readFds;
    FD_ZERO(&master);
    FD_SET(g_listenSock, &master);

    bool hasClientEver = false;
    while (true) {
        readFds = master;
        timeval tv{ 0, SELECT_TO_MS * 1000 };   // 每次 select 最多等 30 秒
        int ret = select(0, &readFds, nullptr, nullptr, &tv);
        if (ret == 0) {
            if (!hasClientEver && g_clients.empty()) {
                std::cout << "No connections within 30s, exiting.\n";
                break;
            }
            continue;
        }
        if (ret < 0) {
            std::cerr << "select error\n";
            break;
        }

        // 检查 listen socket
        if (FD_ISSET(g_listenSock, &readFds)) {
            sockaddr_in cliAddr{};
            int len = sizeof(cliAddr);
            SOCKET cliSock = accept(g_listenSock, (sockaddr*)&cliAddr, &len);
            if (cliSock == INVALID_SOCKET) continue;

            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &cliAddr.sin_addr, ipStr, sizeof(ipStr));
            uint16_t port = ntohs(cliAddr.sin_port);

            g_clients[cliSock] = Client{ cliSock, ipStr, port, "", "" };
            FD_SET(cliSock, &master);
            hasClientEver = true;
            std::cout << "New connection from " << ipStr << ":" << port
                      << ", total clients: " << g_clients.size() << "\n";
        }

        // 检查客户端 socket
        for (auto it = g_clients.begin(); it != g_clients.end();) {
            SOCKET s = it->first;
            if (!FD_ISSET(s, &readFds)) { ++it; continue; }

            char buf[MAX_BUF];
            int n = recv(s, buf, sizeof(buf), 0);
            if (n <= 0) {
                FD_CLR(s, &master);
                closeClient(s);
                it = g_clients.begin();
                continue;
            }
            it->second.recvBuf.append(buf, n);
            processClient(it->second);
            ++it;
        }

        if (g_clients.empty() && hasClientEver) {
            std::cout << "All clients disconnected, server exiting.\n";
            break;
        }
    }

    for (auto& [s, _] : g_clients) closesocket(s);
    closesocket(g_listenSock);
    WSACleanup();
    return 0;
}
