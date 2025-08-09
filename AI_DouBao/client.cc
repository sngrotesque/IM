#include "common.hh"
#include <conio.h>
#include <thread>
#include <iostream>

// 处理用户输入并发送消息
void handleUserInput(SOCKET clientSocket, const std::string& username) {
    std::string input;
    
    while (true) {
        // 读取用户输入
        if (!std::getline(std::cin, input)) {
            break;
        }
        
        // 如果用户输入exit，退出程序
        if (input == "exit") {
            std::cout << "Exiting..." << std::endl;
            closesocket(clientSocket);
            WSACleanup();
            exit(0);
        }
        
        // 创建聊天消息
        ChatMessage msg;
        msg.username = username;
        msg.timestamp = getCurrentTimestamp();
        msg.content = input;
        
        // 序列化并发送消息
        auto data = serializeChatMessage(msg);
        if (!sendMessage(clientSocket, MSG_CHAT, data)) {
            std::cerr << "Failed to send message." << std::endl;
            break;
        }
    }
}

// 接收并处理服务器消息
void receiveMessages(SOCKET clientSocket) {
    while (true) {
        // 读取消息头部
        NetworkHeader header;
        int bytesRead = recv(clientSocket, reinterpret_cast<char*>(&header), sizeof(NetworkHeader), 0);
        
        if (bytesRead <= 0) {
            if (bytesRead == 0) {
                std::cout << "Server closed the connection." << std::endl;
            } else {
                std::cerr << "recv failed. Error: " << WSAGetLastError() << std::endl;
            }
            closesocket(clientSocket);
            WSACleanup();
            exit(1);
        }
        
        // 读取消息数据
        std::vector<uint8_t> data(header.length - sizeof(NetworkHeader));
        if (!data.empty()) {
            bytesRead = recv(clientSocket, reinterpret_cast<char*>(data.data()), data.size(), 0);
            if (bytesRead <= 0) {
                std::cerr << "Failed to receive message data." << std::endl;
                closesocket(clientSocket);
                WSACleanup();
                exit(1);
            }
        }
        
        // 处理不同类型的消息
        switch (header.type) {
            case MSG_LOGIN_RESPONSE: {
                LoginResponse resp;
                if (deserializeLoginResponse(data, resp)) {
                    if (resp.success) {
                        std::cout << resp.message << " You can now start chatting. Type 'exit' to quit." << std::endl;
                    } else {
                        std::cerr << "Login failed: " << resp.message << std::endl;
                        closesocket(clientSocket);
                        WSACleanup();
                        exit(1);
                    }
                }
                break;
            }
            
            case MSG_CHAT: {
                ChatMessage msg;
                if (deserializeChatMessage(data, msg)) {
                    std::cout << "Client " << msg.username << " " 
                              << std::fixed << std::setprecision(6) << msg.timestamp 
                              << ": " << msg.content << std::endl;
                }
                break;
            }
            
            case MSG_SYSTEM: {
                SystemMessage msg;
                if (deserializeSystemMessage(data, msg)) {
                    std::cout << "[System] " << msg.content << std::endl;
                }
                break;
            }
            
            default:
                std::cout << "Received unknown message type." << std::endl;
                break;
        }
    }
}

int main() {
    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed. Error: " << WSAGetLastError() << std::endl;
        return 1;
    }
    
    // 创建客户端Socket
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "socket failed. Error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }
    
    // 服务器地址
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    
    // 输入服务器IP地址
    std::string serverIp;
    std::cout << "Enter server IP address: ";
    std::cin >> serverIp;
    std::cin.ignore(); // 忽略输入缓冲区中的换行符
    
    // 转换IP地址
    if (inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    
    // 连接到服务器
    if (connect(clientSocket, reinterpret_cast<SOCKADDR*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "connect failed. Error: " << WSAGetLastError() << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    
    std::cout << "Connected to server." << std::endl;
    
    // 用户登录
    std::string username, password;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);
    std::cout << "Enter password: ";
    std::getline(std::cin, password);
    
    // 发送登录请求
    LoginRequest loginReq;
    loginReq.username = username;
    loginReq.password = password;
    
    auto loginData = serializeLoginRequest(loginReq);
    if (!sendMessage(clientSocket, MSG_LOGIN, loginData)) {
        std::cerr << "Failed to send login request." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    
    // 等待登录响应（会在receiveMessages线程中处理）
    
    // 创建接收消息的线程
    std::thread receiverThread(receiveMessages, clientSocket);
    receiverThread.detach(); // 分离线程，使其独立运行
    
    // 处理用户输入
    handleUserInput(clientSocket, username);
    
    // 清理资源
    closesocket(clientSocket);
    WSACleanup();
    return 0;
}
