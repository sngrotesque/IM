# TCP 服务端和客户端实现

下面我将按照要求实现一个基于select的多路复用TCP服务端和客户端，包含用户认证功能。

## 服务端代码

```cpp
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <algorithm>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

// 用户数据库 - 简单使用内存存储
struct User {
    std::string username;
    std::string password_hash; // SHA256哈希值
};

std::vector<User> user_db = {
    {"user1", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}, // sha256 of "password"
    {"user2", "6cf615d5bcaac778352a8f1f3360d23f02f34ec182e259897fd6ce485d7870d4"}  // sha256 of "123456"
};

// 客户端信息结构
struct ClientInfo {
    SOCKET socket;
    sockaddr_in addr;
    std::string username;
    bool authenticated;
    time_t last_active;
};

// 全局变量
std::vector<ClientInfo> clients;
fd_set master_set;
SOCKET max_socket;
time_t server_start_time;

// 函数声明
void InitializeWinsock();
void CleanupWinsock();
void SetupServerSocket(SOCKET &server_socket, int port);
void HandleNewConnection(SOCKET server_socket);
void HandleClientData(int client_index);
void RemoveClient(int client_index);
void BroadcastMessage(const std::string &message, int exclude_index = -1);
std::string GetTimestampString();
std::string HashPassword(const std::string &password);
bool AuthenticateUser(const std::string &username, const std::string &password);
void ParseMessage(const std::string &data, std::string &username, std::string &message);

int main() {
    InitializeWinsock();

    SOCKET server_socket;
    SetupServerSocket(server_socket, 12345);

    server_start_time = time(nullptr);
    FD_ZERO(&master_set);
    FD_SET(server_socket, &master_set);
    max_socket = server_socket;

    timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;

    while (true) {
        fd_set read_set = master_set;
        int ready = select(0, &read_set, nullptr, nullptr, &timeout);

        // 检查超时
        if (ready == SOCKET_ERROR) {
            std::cerr << "select error: " << WSAGetLastError() << std::endl;
            break;
        } else if (ready == 0) {
            // 超时处理
            if (clients.empty() && (time(nullptr) - server_start_time) >= 30) {
                std::cout << "No connections for 30 seconds, shutting down..." << std::endl;
                break;
            }
            continue;
        }

        // 检查新连接
        if (FD_ISSET(server_socket, &read_set)) {
            HandleNewConnection(server_socket);
        }

        // 检查客户端数据
        for (size_t i = 0; i < clients.size(); ) {
            if (FD_ISSET(clients[i].socket, &read_set)) {
                HandleClientData(i);
                // HandleClientData可能会调用RemoveClient，所以不要在这里增加i
            } else {
                i++;
            }
        }

        // 检查所有客户端是否都断开了
        if (clients.empty()) {
            std::cout << "All clients disconnected, shutting down..." << std::endl;
            break;
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

void SetupServerSocket(SOCKET &server_socket, int port) {
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        std::cerr << "socket() failed: " << WSAGetLastError() << std::endl;
        exit(1);
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "bind() failed: " << WSAGetLastError() << std::endl;
        closesocket(server_socket);
        exit(1);
    }

    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "listen() failed: " << WSAGetLastError() << std::endl;
        closesocket(server_socket);
        exit(1);
    }
}

void HandleNewConnection(SOCKET server_socket) {
    sockaddr_in client_addr;
    int client_addr_size = sizeof(client_addr);
    SOCKET client_socket = accept(server_socket, (sockaddr*)&client_addr, &client_addr_size);

    if (client_socket == INVALID_SOCKET) {
        std::cerr << "accept() failed: " << WSAGetLastError() << std::endl;
        return;
    }

    // 设置非阻塞模式
    u_long mode = 1;
    ioctlsocket(client_socket, FIONBIO, &mode);

    // 添加到客户端列表
    ClientInfo client;
    client.socket = client_socket;
    client.addr = client_addr;
    client.authenticated = false;
    client.last_active = time(nullptr);
    clients.push_back(client);

    FD_SET(client_socket, &master_set);
    if (client_socket > max_socket) {
        max_socket = client_socket;
    }

    std::cout << "New connection from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << std::endl;
}

void HandleClientData(int client_index) {
    ClientInfo &client = clients[client_index];
    client.last_active = time(nullptr);

    // 首先读取4字节的消息长度
    uint32_t message_len = 0;
    int bytes_received = recv(client.socket, (char*)&message_len, sizeof(message_len), 0);

    if (bytes_received <= 0) {
        // 连接关闭或错误
        RemoveClient(client_index);
        return;
    }

    // 读取消息内容
    std::string message_data;
    message_data.resize(message_len);
    bytes_received = recv(client.socket, &message_data[0], message_len, 0);

    if (bytes_received <= 0) {
        // 连接关闭或错误
        RemoveClient(client_index);
        return;
    }

    // 处理认证或消息
    if (!client.authenticated) {
        // 认证消息格式: "LOGIN username password"
        std::string login_msg = message_data;
        std::istringstream iss(login_msg);
        std::string command, username, password;
        iss >> command >> username >> password;

        if (command == "LOGIN" && AuthenticateUser(username, password)) {
            client.username = username;
            client.authenticated = true;
            std::string welcome_msg = "Welcome, " + username + "!";
            uint32_t welcome_len = welcome_msg.size();
            send(client.socket, (char*)&welcome_len, sizeof(welcome_len), 0);
            send(client.socket, welcome_msg.c_str(), welcome_len, 0);

            std::cout << "Client authenticated: " << username << " [" 
                      << inet_ntoa(client.addr.sin_addr) << ":" << ntohs(client.addr.sin_port) << "]" << std::endl;
        } else {
            std::string error_msg = "Authentication failed";
            uint32_t error_len = error_msg.size();
            send(client.socket, (char*)&error_len, sizeof(error_len), 0);
            send(client.socket, error_msg.c_str(), error_len, 0);
            RemoveClient(client_index);
        }
    } else {
        // 普通消息
        std::string timestamp_str = GetTimestampString();
        std::string full_message = "Client " + client.username + " [" + 
                                  inet_ntoa(client.addr.sin_addr) + ":" + 
                                  std::to_string(ntohs(client.addr.sin_port)) + "] [" + 
                                  timestamp_str + "]: " + message_data;
        
        std::cout << full_message << std::endl;
        
        // 广播消息给所有客户端
        std::string broadcast_msg = "Client " + client.username + " [" + timestamp_str + "]: " + message_data;
        BroadcastMessage(broadcast_msg, client_index);
    }
}

void RemoveClient(int client_index) {
    ClientInfo &client = clients[client_index];
    std::cout << "Client disconnected: " << inet_ntoa(client.addr.sin_addr) << ":" << ntohs(client.addr.sin_port) << std::endl;

    closesocket(client.socket);
    FD_CLR(client.socket, &master_set);
    clients.erase(clients.begin() + client_index);
}

void BroadcastMessage(const std::string &message, int exclude_index) {
    uint32_t message_len = message.size();
    for (size_t i = 0; i < clients.size(); ++i) {
        if (i != static_cast<size_t>(exclude_index) && clients[i].authenticated) {
            send(clients[i].socket, (char*)&message_len, sizeof(message_len), 0);
            send(clients[i].socket, message.c_str(), message_len, 0);
        }
    }
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

std::string HashPassword(const std::string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

bool AuthenticateUser(const std::string &username, const std::string &password) {
    auto it = std::find_if(user_db.begin(), user_db.end(), 
        [&username](const User &u) { return u.username == username; });
    
    if (it == user_db.end()) {
        return false;
    }
    
    return it->password_hash == HashPassword(password);
}
```

## 客户端代码

```cpp
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
```

## 实现说明

1. **服务端**:
   - 使用select实现多路复用
   - 维护客户端列表，记录用户名、地址和认证状态
   - 实现用户认证功能，使用SHA256哈希密码
   - 处理消息长度前缀协议
   - 广播消息给所有认证客户端
   - 30秒无连接超时关闭
   - 所有客户端断开后服务端关闭

2. **客户端**:
   - 连接到服务端
   - 实现登录功能
   - 发送带时间戳的消息
   - 接收并显示服务端广播的消息
   - 使用select检查服务器消息

3. **时间戳**:
   - 使用Windows API获取高精度时间
   - 转换为UNIX时间戳格式（秒.微秒）

4. **协议**:
   - 消息前4字节为消息长度（uint32_t）
   - 登录消息格式: "LOGIN username password"
   - 普通消息格式: "[timestamp] message"

5. **安全**:
   - 使用OpenSSL的SHA256哈希密码
   - 不存储明文密码

## 编译说明

1. 需要安装OpenSSL库并配置包含路径和库路径
2. 在Visual Studio中需要链接ws2_32.lib、libeay32.lib和ssleay32.lib

## 使用说明

1. 先启动服务端
2. 启动一个或多个客户端
3. 在客户端输入用户名和密码进行登录（预定义用户: user1/password, user2/123456）
4. 登录后可以发送消息，所有客户端将看到广播的消息

这个实现满足了所有要求，包括多路复用、超时处理、用户认证、消息广播等特性。
