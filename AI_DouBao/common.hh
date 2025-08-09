#ifndef COMMON_H
#define COMMON_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")

// 消息类型
enum MessageType {
    MSG_LOGIN = 1,
    MSG_LOGIN_RESPONSE,
    MSG_CHAT,
    MSG_SYSTEM
};

// 登录请求结构
struct LoginRequest {
    std::string username;
    std::string password;
};

// 登录响应结构
struct LoginResponse {
    bool success;
    std::string message;
};

// 聊天消息结构
struct ChatMessage {
    std::string username;
    double timestamp;
    std::string content;
};

// 系统消息结构
struct SystemMessage {
    std::string content;
};

// 网络消息头部
struct NetworkHeader {
    uint32_t length;  // 消息总长度（包括头部）
    uint8_t type;     // 消息类型
};

// 客户端信息结构
struct ClientInfo {
    SOCKET socket;
    sockaddr_in address;
    std::string username;
    bool loggedIn;
};

// 常量定义
const int BUFFER_SIZE = 4096;
const int TIMEOUT_SECONDS = 30;
const int SALT_LENGTH = 16;
const int HASH_LENGTH = 32;

// 工具函数：将字符串转换为网络字节流
std::vector<uint8_t> stringToBytes(const std::string& str);

// 工具函数：将网络字节流转换为字符串
std::string bytesToString(const std::vector<uint8_t>& bytes);

// 工具函数：获取当前Unix时间戳（包含微秒）
double getCurrentTimestamp();

// 工具函数：生成随机盐值
void generateSalt(uint8_t* salt, int length);

// 工具函数：使用SHA-256哈希密码
bool hashPassword(const std::string& password, const uint8_t* salt, uint8_t* hash);

// 工具函数：序列化登录请求
std::vector<uint8_t> serializeLoginRequest(const LoginRequest& req);

// 工具函数：反序列化登录请求
bool deserializeLoginRequest(const std::vector<uint8_t>& data, LoginRequest& req);

// 工具函数：序列化登录响应
std::vector<uint8_t> serializeLoginResponse(const LoginResponse& resp);

// 工具函数：反序列化登录响应
bool deserializeLoginResponse(const std::vector<uint8_t>& data, LoginResponse& resp);

// 工具函数：序列化聊天消息
std::vector<uint8_t> serializeChatMessage(const ChatMessage& msg);

// 工具函数：反序列化聊天消息
bool deserializeChatMessage(const std::vector<uint8_t>& data, ChatMessage& msg);

// 工具函数：序列化系统消息
std::vector<uint8_t> serializeSystemMessage(const SystemMessage& msg);

// 工具函数：反序列化系统消息
bool deserializeSystemMessage(const std::vector<uint8_t>& data, SystemMessage& msg);

// 工具函数：发送消息
bool sendMessage(SOCKET s, uint8_t type, const std::vector<uint8_t>& data);

#endif // COMMON_H
