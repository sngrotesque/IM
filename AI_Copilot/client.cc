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
