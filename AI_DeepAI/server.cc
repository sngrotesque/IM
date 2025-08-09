#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <chrono>
#include <openssl/evp.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

struct ClientInfo {
    SOCKET sock;
    std::string username;
    sockaddr_in addr;
    bool logged_in;
};

// 全局变量
std::vector<ClientInfo> clients;
std::string server_password_hash; // 存储密码的哈希

// 加载密码（示例，实际应用中存储哈希值）
void load_password_hash() {
    // 这里假设密码是"password123"
    const char* password = "password123";
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char hash[32];
    unsigned int length = 0;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, password, strlen(password));
    EVP_DigestFinal_ex(ctx, hash, &length);
    EVP_MD_CTX_free(ctx);

    server_password_hash.assign((char*)hash, length);
}

// 简单密码验证
bool verify_password(const std::string& password) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char hash[32];
    unsigned int length = 0;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, password.c_str(), password.size());
    EVP_DigestFinal_ex(ctx, hash, &length);
    EVP_MD_CTX_free(ctx);
    return server_password_hash == std::string((char*)hash, length);
}

// 获取当前时间戳（秒+微秒）
std::string get_timestamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto sec = duration_cast<seconds>(now.time_since_epoch()).count();
    auto micro = duration_cast<microseconds>(now.time_since_epoch()).count() % 1000000;
    char buf[64];
    sprintf(buf, "%lld.%06lld", sec, micro);
    return std::string(buf);
}

// 发送消息（带长度前缀）
bool send_message(SOCKET sock, const std::string& msg) {
    uint32_t len = (uint32_t)msg.size();
    std::vector<char> buffer(4 + len);
    memcpy(buffer.data(), &len, 4);
    memcpy(buffer.data() + 4, msg.data(), len);
    int sent = send(sock, buffer.data(), buffer.size(), 0);
    return sent == buffer.size();
}

// 接收固定长度数据
bool recv_fixed(SOCKET sock, char* buf, int len) {
    int received = 0;
    while (received < len) {
        int r = recv(sock, buf + received, len - received, 0);
        if (r <= 0) return false;
        received += r;
    }
    return true;
}

// 读取完整消息
bool recv_message(SOCKET sock, std::string& outMsg) {
    uint32_t len = 0;
    if (!recv_fixed(sock, (char*)&len, 4)) return false;
    std::vector<char> buf(len);
    if (!recv_fixed(sock, buf.data(), len)) return false;
    outMsg.assign(buf.begin(), buf.end());
    return true;
}

// 广播消息
void broadcast(const std::string& message, SOCKET exclude_sock = INVALID_SOCKET) {
    for (auto& client : clients) {
        if (client.sock != exclude_sock) {
            send_message(client.sock, message);
        }
    }
}

// 处理新连接的客户端
void handle_new_client(SOCKET listen_sock) {
    sockaddr_in client_addr;
    int addrlen = sizeof(client_addr);
    SOCKET client_sock = accept(listen_sock, (sockaddr*)&client_addr, &addrlen);
    if (client_sock == INVALID_SOCKET) return;

    // 设置非阻塞
    // u_long mode = 1;
    // ioctlsocket(client_sock, FIONBIO, &mode);

    ClientInfo ci;
    ci.sock = client_sock;
    ci.addr = client_addr;
    ci.logged_in = false;
    ci.username = "";
    clients.push_back(ci);
    std::cout << "New client connected from "
              << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "\n";
}

// 关闭客户端连接
void close_client(ClientInfo& client) {
    closesocket(client.sock);
    // 移除
    clients.erase(std::remove_if(clients.begin(), clients.end(),
        [&](const ClientInfo& c) { return c.sock == client.sock; }), clients.end());
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    load_password_hash();

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(12345);

    bind(listen_sock, (sockaddr*)&server_addr, sizeof(server_addr));
    listen(listen_sock, SOMAXCONN);
    std::cout << "Server listening on port 12345\n";

    // 设置超时
    timeval timeout{};
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;

    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listen_sock, &readfds);
        int max_fd = listen_sock;

        for (auto& client : clients) {
            FD_SET(client.sock, &readfds);
            if (client.sock > max_fd) max_fd = client.sock;
        }

        int ret = select(max_fd + 1, &readfds, NULL, NULL, &timeout);
        if (ret == 0) {
            // 超时
            std::cout << "Timeout: no activity for 30 seconds, shutting down.\n";
            break;
        } else if (ret < 0) {
            std::cerr << "select() failed.\n";
            break;
        }

        // 处理新连接
        if (FD_ISSET(listen_sock, &readfds)) {
            handle_new_client(listen_sock);
        }

        // 处理已有客户端
        for (auto it = clients.begin(); it != clients.end(); ) {
            if (FD_ISSET(it->sock, &readfds)) {
                std::string msg;
                int recv_result = recv_message(it->sock, msg);
                if (!recv_result || msg.empty()) {
                    // 客户端关闭
                    std::cout << "Client disconnected from "
                              << inet_ntoa(it->addr.sin_addr) << ":" << ntohs(it->addr.sin_port) << "\n";
                    closesocket(it->sock);
                    it = clients.erase(it);
                    continue;
                }

                // 处理消息
                if (!it->logged_in) {
                    // 第一次需验证密码
                    // 假设客户端发送密码（明文）
                    if (verify_password(msg)) {
                        it->logged_in = true;
                        // 这里可以请求提供用户名
                        send_message(it->sock, "Please send your username");
                        // 需要后续接收用户名
                        // 简化：假设第一条消息就是用户名
                        // 实际应有状态管理
                        // 这里为简化示例
                        it->username = "User"; // 这里应由客户端发来
                    } else {
                        send_message(it->sock, "Invalid password");
                        closesocket(it->sock);
                        it = clients.erase(it);
                        continue;
                    }
                } else {
                    // 已登录，处理消息
                    // 消息格式： [消息内容]
                    std::string timestamp = get_timestamp();
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &it->addr.sin_addr, ip_str, INET_ADDRSTRLEN);
                    int port = ntohs(it->addr.sin_port);
                    std::string display_msg = "Client " + it->username + " [" + std::string(ip_str) + ":" + std::to_string(port) + "] " +
                                              "[" + timestamp + "]: " + msg;
                    std::cout << display_msg << "\n";

                    // 广播
                    std::string broadcast_msg = "Client " + it->username + " [" + std::string(ip_str) + ":" + std::to_string(port) + "] " +
                                                "[" + timestamp + "]: " + msg;
                    broadcast(broadcast_msg, it->sock);
                }
                ++it;
            } else {
                ++it;
            }
        }

        // 如果没有客户端连接且无活动，则退出
        if (clients.empty()) {
            std::cout << "No clients connected. Shutting down.\n";
            break;
        }
    }

    // 关闭所有客户端
    for (auto& client : clients) {
        closesocket(client.sock);
    }
    closesocket(listen_sock);
    WSACleanup();
    return 0;
}
