#include <iostream>
#include <string>
#include <ctime>
#include <iomanip>
#include <sstream>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

// 函数声明
void InitializeWinsock();
void CleanupWinsock();
SOCKET ConnectToServer(const std::string &host, int port);
void SendMessageToServer(SOCKET socket, const std::string &message);
std::string ReceiveMessage(SOCKET socket);
std::string GetTimestampString();
std::string GetLoginMessage(const std::string &username, const std::string &password);

int main() {
    InitializeWinsock();

    SOCKET server_socket = ConnectToServer("127.0.0.1", 12345);
    if (server_socket == INVALID_SOCKET) {
        CleanupWinsock();
        return 1;
    }

    // 用户登录
    std::string username, password;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);
    std::cout << "Enter password: ";
    std::getline(std::cin, password);

    SendMessageToServer(server_socket, GetLoginMessage(username, password));

    // 接收欢迎消息或错误
    std::string response = ReceiveMessage(server_socket);
    if (response.find("Welcome") == std::string::npos) {
        std::cerr << "Login failed: " << response << std::endl;
        closesocket(server_socket);
        CleanupWinsock();
        return 1;
    }

    std::cout << "Login successful! You can now send messages." << std::endl;

    // 主循环
    while (true) {
        // 检查服务器消息
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(server_socket, &read_set);

        timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // 100ms

        int ready = select(0, &read_set, nullptr, nullptr, &timeout);
        if (ready == SOCKET_ERROR) {
            std::cerr << "select error: " << WSAGetLastError() << std::endl;
            break;
        }

        if (ready > 0 && FD_ISSET(server_socket, &read_set)) {
            std::string server_message = ReceiveMessage(server_socket);
            if (server_message.empty()) {
                std::cout << "Server disconnected" << std::endl;
                break;
            }
            std::cout << server_message << std::endl;
        }

        // 检查用户输入
        if (_kbhit()) {
            std::string user_input;
            std::getline(std::cin, user_input);

            if (user_input == "/exit") {
                break;
            }

            // 添加时间戳
            std::string timestamp_str = GetTimestampString();
            std::string message_with_timestamp = "[" + timestamp_str + "] " + user_input;
            
            SendMessageToServer(server_socket, message_with_timestamp);
        }
    }

    closesocket(server_socket);
    CleanupWinsock();
    return 0;
}

void InitializeWinsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        exit(1);
    }
}

void CleanupWinsock() {
    WSACleanup();
}

SOCKET ConnectToServer(const std::string &host, int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "socket() failed: " << WSAGetLastError() << std::endl;
        return INVALID_SOCKET;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr);

    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "connect() failed: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}

void SendMessageToServer(SOCKET socket, const std::string &message) {
    uint32_t message_len = message.size();
    send(socket, (char*)&message_len, sizeof(message_len), 0);
    send(socket, message.c_str(), message_len, 0);
}

std::string ReceiveMessage(SOCKET socket) {
    // 首先读取4字节的消息长度
    uint32_t message_len = 0;
    int bytes_received = recv(socket, (char*)&message_len, sizeof(message_len), 0);

    if (bytes_received <= 0) {
        return "";
    }

    // 读取消息内容
    std::string message_data;
    message_data.resize(message_len);
    bytes_received = recv(socket, &message_data[0], message_len, 0);

    if (bytes_received <= 0) {
        return "";
    }

    return message_data;
}

std::string GetTimestampString() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    // 转换为UNIX时间戳（100纳秒单位从1601-01-01到1970-01-01的偏移量）
    uli.QuadPart -= 116444736000000000ULL;

    // 转换为秒和微秒
    double timestamp = static_cast<double>(uli.QuadPart) / 10000000.0;
    double seconds = floor(timestamp);
    double microseconds = (timestamp - seconds) * 1000000.0;

    // 格式化输出
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6) << seconds << "." << static_cast<uint32_t>(microseconds);
    return oss.str();
}

std::string GetLoginMessage(const std::string &username, const std::string &password) {
    return "LOGIN " + username + " " + password;
}
