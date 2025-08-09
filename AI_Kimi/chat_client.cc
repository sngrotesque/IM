/****************************************************************************************
 *  Chat Client
 *  Windows / C++17 / TCP
 *
 *  编译：
 *      cl /std:c++17 /EHsc /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS ^
 *         chat_client.cpp ws2_32.lib /Fe:chat_client.exe
 *
 *  运行：
 *      chat_client.exe 127.0.0.1 12345
 ****************************************************************************************/
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

#pragma comment(lib,"ws2_32.lib")

const int MAX_BUF = 4096;

void die(const char* msg) {
    std::cerr << msg << " (" << WSAGetLastError() << ")\n";
    WSACleanup();
    exit(1);
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

std::string recvAll(SOCKET s) {
    uint32_t len = 0;
    int n = recv(s, (char*)&len, 4, MSG_WAITALL);
    if (n != 4) return "";
    len = *(uint32_t*)&len;
    std::string buf(len, '\0');
    n = recv(s, buf.data(), len, MSG_WAITALL);
    if (n != (int)len) return "";
    return buf;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: chat_client.exe <ip> <port>\n";
        return 1;
    }
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) die("WSAStartup");

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) die("socket");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(std::stoi(argv[2]));
    inet_pton(AF_INET, argv[1], &addr.sin_addr);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
        die("connect");

    std::cout << "Connected to server. Please login.\n";

    // 登录
    while (true) {
        std::string user, pass;
        std::cout << "Username: "; std::getline(std::cin, user);
        std::cout << "Password: "; std::getline(std::cin, pass);
        std::string payload = user + "\n" + pass;
        sendAll(sock, payload);
        std::string resp = recvAll(sock);
        if (resp == "Login failed.") {
            std::cout << resp << "\n";
            closesocket(sock);
            return 1;
        }
        std::cout << resp << "\n";
        break;
    }

    // 接收线程
    std::thread recvThr([&sock]() {
        while (true) {
            std::string msg = recvAll(sock);
            if (msg.empty()) break;
            std::cout << msg << "\n";
        }
    });

    // 主线程：读取 stdin 并发送
    std::string line;
    while (std::getline(std::cin, line)) {
        if (!sendAll(sock, line)) break;
    }

    recvThr.join();
    closesocket(sock);
    WSACleanup();
    return 0;
}
