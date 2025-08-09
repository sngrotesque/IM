#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <chrono>

#pragma comment(lib, "Ws2_32.lib")

// 发送消息（带长度前缀）
bool send_message(SOCKET sock, const std::string& msg) {
    uint32_t len = (uint32_t)msg.size();
    std::vector<char> buffer(4 + len);
    memcpy(buffer.data(), &len, 4);
    memcpy(buffer.data() + 4, msg.data(), len);
    int sent = send(sock, buffer.data(), buffer.size(), 0);
    return sent == buffer.size();
}

// 获取时间戳
std::string get_timestamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto sec = duration_cast<seconds>(now.time_since_epoch()).count();
    auto micro = duration_cast<microseconds>(now.time_since_epoch()).count() % 1000000;
    char buf[64];
    sprintf(buf, "%lld.%06lld", sec, micro);
    return std::string(buf);
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
    server_addr.sin_port = htons(12345);

    connect(sock, (sockaddr*)&server_addr, sizeof(server_addr));
    std::cout << "Connected to server.\n";

    // 先发送密码
    std::string password = "password123";
    send_message(sock, password);
    // 这里应等待服务器确认，简化处理
    // 发送用户名
    std::string username = "MyUser";
    send_message(sock, username);

    // 发送消息
    while (true) {
        std::cout << "Enter message: ";
        std::string msg;
        std::getline(std::cin, msg);
        // 可以加入时间戳
        std::string timestamp = get_timestamp();
        std::string full_msg = msg; // 也可以在协议中加入时间戳
        send_message(sock, full_msg);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
