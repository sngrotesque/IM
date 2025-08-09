#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 4096

std::string get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration - seconds);
    
    return std::to_string(seconds.count()) + "." + std::to_string(microseconds.count());
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> <username:password>" << std::endl;
        return 1;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed: " << WSAGetLastError() << std::endl;
        return 1;
    }

    SOCKET client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client_socket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(argv[1]);
    server_addr.sin_port = htons(static_cast<u_short>(std::stoi(argv[2])));

    if (connect(client_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed: " << WSAGetLastError() << std::endl;
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    // 发送认证信息
    std::string auth_info = argv[3];
    send(client_socket, auth_info.c_str(), auth_info.size(), 0);

    std::atomic<bool> running(true);

    // 接收线程
    std::thread receiver([&]() {
        while (running) {
            // 先读取消息长度
            uint32_t msg_length;
            int bytes_received = recv(client_socket, (char*)&msg_length, sizeof(msg_length), 0);
            
            if (bytes_received <= 0) {
                std::cerr << "Server disconnected" << std::endl;
                running = false;
                break;
            }

            // 然后读取消息内容
            std::vector<char> buffer(msg_length + 1);
            bytes_received = recv(client_socket, buffer.data(), msg_length, 0);
            
            if (bytes_received <= 0) {
                std::cerr << "Error receiving message from server" << std::endl;
                running = false;
                break;
            }

            buffer[bytes_received] = '\0';
            std::cout << buffer.data() << std::endl;
        }
    });

    // 发送线程
    while (running) {
        std::string input;
        std::getline(std::cin, input);
        
        if (input == "exit") {
            running = false;
            break;
        }

        // 准备消息，包含时间戳
        std::string timestamp = get_current_timestamp();
        std::string message = timestamp + ":" + input;
        
        // 发送消息长度前缀
        uint32_t msg_length = static_cast<uint32_t>(message.size());
        send(client_socket, (const char*)&msg_length, sizeof(msg_length), 0);
        
        // 发送消息内容
        send(client_socket, message.c_str(), message.size(), 0);
    }

    // 清理
    running = false;
    receiver.join();
    closesocket(client_socket);
    WSACleanup();

    return 0;
}
