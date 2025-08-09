#include "common.hh"
#include <map>
#include <fstream>
#include <algorithm>

// 用户信息结构
struct User {
    std::string username;
    uint8_t salt[SALT_LENGTH];
    uint8_t hash[HASH_LENGTH];
};

// 从文件加载用户信息
bool loadUsers(const std::string& filename, std::map<std::string, User>& users) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    // 读取用户数量
    uint32_t userCount;
    file.read(reinterpret_cast<char*>(&userCount), sizeof(userCount));
    
    for (uint32_t i = 0; i < userCount; ++i) {
        User user;
        
        // 读取用户名长度和内容
        uint32_t usernameLen;
        file.read(reinterpret_cast<char*>(&usernameLen), sizeof(usernameLen));
        
        user.username.resize(usernameLen);
        file.read(&user.username[0], usernameLen);
        
        // 读取盐值
        file.read(reinterpret_cast<char*>(user.salt), SALT_LENGTH);
        
        // 读取哈希值
        file.read(reinterpret_cast<char*>(user.hash), HASH_LENGTH);
        
        users[user.username] = user;
    }
    
    return true;
}

// 保存用户信息到文件
bool saveUsers(const std::string& filename, const std::map<std::string, User>& users) {
    std::ofstream file(filename, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    
    // 写入用户数量
    uint32_t userCount = static_cast<uint32_t>(users.size());
    file.write(reinterpret_cast<const char*>(&userCount), sizeof(userCount));
    
    for (const auto& pair : users) {
        const User& user = pair.second;
        
        // 写入用户名长度和内容
        uint32_t usernameLen = static_cast<uint32_t>(user.username.length());
        file.write(reinterpret_cast<const char*>(&usernameLen), sizeof(usernameLen));
        file.write(user.username.c_str(), usernameLen);
        
        // 写入盐值
        file.write(reinterpret_cast<const char*>(user.salt), SALT_LENGTH);
        
        // 写入哈希值
        file.write(reinterpret_cast<const char*>(user.hash), HASH_LENGTH);
    }
    
    return true;
}

// 添加新用户
bool addUser(const std::string& username, const std::string& password, 
             std::map<std::string, User>& users, const std::string& filename) {
    if (users.find(username) != users.end()) {
        return false; // 用户已存在
    }
    
    User user;
    user.username = username;
    
    // 生成盐值
    generateSalt(user.salt, SALT_LENGTH);
    
    // 计算密码哈希
    if (!hashPassword(password, user.salt, user.hash)) {
        return false;
    }
    
    users[username] = user;
    return saveUsers(filename, users);
}

// 验证用户
bool verifyUser(const std::string& username, const std::string& password, 
               const std::map<std::string, User>& users) {
    auto it = users.find(username);
    if (it == users.end()) {
        return false; // 用户不存在
    }
    
    const User& user = it->second;
    uint8_t computedHash[HASH_LENGTH];
    
    if (!hashPassword(password, user.salt, computedHash)) {
        return false;
    }
    
    // 比较计算出的哈希与存储的哈希
    return memcmp(computedHash, user.hash, HASH_LENGTH) == 0;
}

// 广播消息给所有已登录的客户端
void broadcastMessage(const std::vector<uint8_t>& data, uint8_t type, 
                     const std::vector<ClientInfo>& clients, SOCKET serverSocket) {
    for (const auto& client : clients) {
        if (client.socket != serverSocket && client.loggedIn) {
            sendMessage(client.socket, type, data);
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
    
    // 创建服务器Socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "socket failed. Error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }
    
    // 绑定Socket到端口
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(12345);
    
    if (bind(serverSocket, reinterpret_cast<SOCKADDR*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "bind failed. Error: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }
    
    // 开始监听
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "listen failed. Error: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }
    
    std::cout << "Server started. Listening on port 12345..." << std::endl;
    
    // 加载用户信息
    std::map<std::string, User> users;
    if (!loadUsers("users.dat", users)) {
        std::cout << "No existing users found. Creating new user database." << std::endl;
        // 可以在这里添加默认管理员用户
        // addUser("admin", "admin123", users, "users.dat");
    }
    
    // 客户端列表
    std::vector<ClientInfo> clients;
    
    // 主循环
    while (true) {
        // 设置文件描述符集
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(serverSocket, &readSet);
        
        SOCKET maxSocket = serverSocket;
        
        // 添加所有客户端Socket到集合
        for (const auto& client : clients) {
            FD_SET(client.socket, &readSet);
            if (client.socket > maxSocket) {
                maxSocket = client.socket;
            }
        }
        
        // 设置超时时间
        timeval timeout;
        timeout.tv_sec = TIMEOUT_SECONDS;
        timeout.tv_usec = 0;
        
        // 调用select
        int activity = select(0, &readSet, nullptr, nullptr, &timeout);
        if (activity == SOCKET_ERROR) {
            std::cerr << "select failed. Error: " << WSAGetLastError() << std::endl;
            break;
        } else if (activity == 0) {
            // 超时且无客户端连接
            if (clients.empty()) {
                std::cout << "Timeout reached with no connections. Closing server." << std::endl;
                break;
            } else {
                std::cout << "Timeout reached, but there are still clients connected." << std::endl;
                continue;
            }
        }
        
        // 检查新的连接
        if (FD_ISSET(serverSocket, &readSet)) {
            sockaddr_in clientAddr;
            int clientAddrSize = sizeof(clientAddr);
            
            SOCKET clientSocket = accept(serverSocket, reinterpret_cast<SOCKADDR*>(&clientAddr), &clientAddrSize);
            if (clientSocket == INVALID_SOCKET) {
                std::cerr << "accept failed. Error: " << WSAGetLastError() << std::endl;
                continue;
            }
            
            // 将新客户端添加到列表
            ClientInfo newClient;
            newClient.socket = clientSocket;
            newClient.address = clientAddr;
            newClient.loggedIn = false;
            clients.push_back(newClient);
            
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(clientAddr.sin_addr), ipStr, INET_ADDRSTRLEN);
            std::cout << "New connection from " << ipStr << ":" << ntohs(clientAddr.sin_port) << std::endl;
        }
        
        // 检查客户端消息
        for (size_t i = 0; i < clients.size();) {
            ClientInfo& client = clients[i];
            
            if (FD_ISSET(client.socket, &readSet)) {
                // 读取消息头部
                NetworkHeader header;
                int bytesRead = recv(client.socket, reinterpret_cast<char*>(&header), sizeof(NetworkHeader), 0);
                
                if (bytesRead <= 0) {
                    // 客户端断开连接
                    char ipStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(client.address.sin_addr), ipStr, INET_ADDRSTRLEN);
                    std::cout << "Client " << ipStr << ":" << ntohs(client.address.sin_port);
                    
                    if (client.loggedIn) {
                        std::cout << " (" << client.username << ")";
                    }
                    
                    std::cout << " disconnected." << std::endl;
                    
                    // 关闭Socket并从列表中移除
                    closesocket(client.socket);
                    clients.erase(clients.begin() + i);
                    
                    // 如果所有客户端都断开连接，关闭服务器
                    if (clients.empty()) {
                        std::cout << "All clients disconnected. Closing server." << std::endl;
                        closesocket(serverSocket);
                        WSACleanup();
                        return 0;
                    }
                    
                    continue;
                }
                
                // 读取消息数据
                std::vector<uint8_t> data(header.length - sizeof(NetworkHeader));
                if (!data.empty()) {
                    bytesRead = recv(client.socket, reinterpret_cast<char*>(data.data()), data.size(), 0);
                    if (bytesRead <= 0) {
                        // 处理错误或断开连接
                        closesocket(client.socket);
                        clients.erase(clients.begin() + i);
                        continue;
                    }
                }
                
                // 处理不同类型的消息
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(client.address.sin_addr), ipStr, INET_ADDRSTRLEN);
                uint16_t port = ntohs(client.address.sin_port);
                
                switch (header.type) {
                    case MSG_LOGIN: {
                        LoginRequest req;
                        if (deserializeLoginRequest(data, req)) {
                            bool success = verifyUser(req.username, req.password, users);
                            LoginResponse resp;
                            
                            if (success) {
                                // 检查用户名是否已登录
                                bool alreadyLoggedIn = false;
                                for (const auto& c : clients) {
                                    if (c.loggedIn && c.username == req.username) {
                                        alreadyLoggedIn = true;
                                        break;
                                    }
                                }
                                
                                if (alreadyLoggedIn) {
                                    resp.success = false;
                                    resp.message = "Username is already logged in.";
                                } else {
                                    resp.success = true;
                                    resp.message = "Login successful.";
                                    client.username = req.username;
                                    client.loggedIn = true;
                                    
                                    std::cout << "Client " << ipStr << ":" << port 
                                              << " logged in as " << req.username << std::endl;
                                    
                                    // 广播用户登录消息
                                    SystemMessage sysMsg;
                                    sysMsg.content = req.username + " has joined the chat.";
                                    auto sysData = serializeSystemMessage(sysMsg);
                                    broadcastMessage(sysData, MSG_SYSTEM, clients, serverSocket);
                                }
                            } else {
                                resp.success = false;
                                resp.message = "Invalid username or password.";
                            }
                            
                            auto respData = serializeLoginResponse(resp);
                            sendMessage(client.socket, MSG_LOGIN_RESPONSE, respData);
                        }
                        break;
                    }
                    
                    case MSG_CHAT: {
                        if (client.loggedIn) {
                            ChatMessage msg;
                            if (deserializeChatMessage(data, msg)) {
                                // 在服务器端显示消息
                                std::cout << "Client " << msg.username << " " 
                                          << ipStr << ":" << port << " " 
                                          << std::fixed << std::setprecision(6) << msg.timestamp 
                                          << ": " << msg.content << std::endl;
                                
                                // 广播消息给所有客户端
                                auto broadcastData = serializeChatMessage(msg);
                                broadcastMessage(broadcastData, MSG_CHAT, clients, serverSocket);
                            }
                        } else {
                            // 未登录用户尝试发送消息
                            LoginResponse resp;
                            resp.success = false;
                            resp.message = "Please login first.";
                            auto respData = serializeLoginResponse(resp);
                            sendMessage(client.socket, MSG_LOGIN_RESPONSE, respData);
                        }
                        break;
                    }
                    
                    default:
                        std::cout << "Received unknown message type from " << ipStr << ":" << port << std::endl;
                        break;
                }
            }
            
            i++;
        }
    }
    
    // 清理资源
    closesocket(serverSocket);
    for (const auto& client : clients) {
        closesocket(client.socket);
    }
    
    WSACleanup();
    return 0;
}
