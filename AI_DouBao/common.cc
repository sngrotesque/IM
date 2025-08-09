#include "common.hh"

std::vector<uint8_t> stringToBytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string bytesToString(const std::vector<uint8_t>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

double getCurrentTimestamp() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    
    // 转换为Unix时间戳（从1970-01-01开始的秒数，包含微秒）
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    
    // Windows文件时间是100纳秒为单位，从1601-01-01开始
    // 计算与Unix时间起点的差值（秒）
    const uint64_t EPOCH_DIFFERENCE = 116444736000000000ULL;
    uint64_t fileTime = uli.QuadPart - EPOCH_DIFFERENCE;
    
    // 转换为秒和微秒
    return static_cast<double>(fileTime) / 10000000.0;
}

void generateSalt(uint8_t* salt, int length) {
    RAND_bytes(salt, length);
}

bool hashPassword(const std::string& password, const uint8_t* salt, uint8_t* hash) {
    const EVP_MD* md = EVP_get_digestbyname("sha256");
    if (!md) return false;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    // 先更新盐值
    if (EVP_DigestUpdate(ctx, salt, SALT_LENGTH) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    // 再更新密码
    if (EVP_DigestUpdate(ctx, password.c_str(), password.length()) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    unsigned int hashLen;
    if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1 || hashLen != HASH_LENGTH) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    EVP_MD_CTX_free(ctx);
    return true;
}

std::vector<uint8_t> serializeLoginRequest(const LoginRequest& req) {
    std::vector<uint8_t> data;
    
    // 序列化用户名长度和内容
    uint32_t usernameLen = static_cast<uint32_t>(req.username.length());
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&usernameLen), 
               reinterpret_cast<const uint8_t*>(&usernameLen) + sizeof(usernameLen));
    data.insert(data.end(), req.username.begin(), req.username.end());
    
    // 序列化密码长度和内容
    uint32_t passwordLen = static_cast<uint32_t>(req.password.length());
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&passwordLen), 
               reinterpret_cast<const uint8_t*>(&passwordLen) + sizeof(passwordLen));
    data.insert(data.end(), req.password.begin(), req.password.end());
    
    return data;
}

bool deserializeLoginRequest(const std::vector<uint8_t>& data, LoginRequest& req) {
    size_t pos = 0;
    
    // 反序列化用户名
    if (pos + sizeof(uint32_t) > data.size()) return false;
    uint32_t usernameLen = *reinterpret_cast<const uint32_t*>(&data[pos]);
    pos += sizeof(uint32_t);
    
    if (pos + usernameLen > data.size()) return false;
    req.username = std::string(data.begin() + pos, data.begin() + pos + usernameLen);
    pos += usernameLen;
    
    // 反序列化密码
    if (pos + sizeof(uint32_t) > data.size()) return false;
    uint32_t passwordLen = *reinterpret_cast<const uint32_t*>(&data[pos]);
    pos += sizeof(uint32_t);
    
    if (pos + passwordLen > data.size()) return false;
    req.password = std::string(data.begin() + pos, data.begin() + pos + passwordLen);
    
    return true;
}

std::vector<uint8_t> serializeLoginResponse(const LoginResponse& resp) {
    std::vector<uint8_t> data;
    
    // 序列化成功标志
    data.push_back(resp.success ? 1 : 0);
    
    // 序列化消息长度和内容
    uint32_t msgLen = static_cast<uint32_t>(resp.message.length());
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&msgLen), 
               reinterpret_cast<const uint8_t*>(&msgLen) + sizeof(msgLen));
    data.insert(data.end(), resp.message.begin(), resp.message.end());
    
    return data;
}

bool deserializeLoginResponse(const std::vector<uint8_t>& data, LoginResponse& resp) {
    if (data.empty()) return false;
    
    // 反序列化成功标志
    resp.success = data[0] == 1;
    size_t pos = 1;
    
    // 反序列化消息
    if (pos + sizeof(uint32_t) > data.size()) return false;
    uint32_t msgLen = *reinterpret_cast<const uint32_t*>(&data[pos]);
    pos += sizeof(uint32_t);
    
    if (pos + msgLen > data.size()) return false;
    resp.message = std::string(data.begin() + pos, data.begin() + pos + msgLen);
    
    return true;
}

std::vector<uint8_t> serializeChatMessage(const ChatMessage& msg) {
    std::vector<uint8_t> data;
    
    // 序列化用户名长度和内容
    uint32_t usernameLen = static_cast<uint32_t>(msg.username.length());
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&usernameLen), 
               reinterpret_cast<const uint8_t*>(&usernameLen) + sizeof(usernameLen));
    data.insert(data.end(), msg.username.begin(), msg.username.end());
    
    // 序列化时间戳
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&msg.timestamp), 
               reinterpret_cast<const uint8_t*>(&msg.timestamp) + sizeof(msg.timestamp));
    
    // 序列化消息内容长度和内容
    uint32_t contentLen = static_cast<uint32_t>(msg.content.length());
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&contentLen), 
               reinterpret_cast<const uint8_t*>(&contentLen) + sizeof(contentLen));
    data.insert(data.end(), msg.content.begin(), msg.content.end());
    
    return data;
}

bool deserializeChatMessage(const std::vector<uint8_t>& data, ChatMessage& msg) {
    size_t pos = 0;
    
    // 反序列化用户名
    if (pos + sizeof(uint32_t) > data.size()) return false;
    uint32_t usernameLen = *reinterpret_cast<const uint32_t*>(&data[pos]);
    pos += sizeof(uint32_t);
    
    if (pos + usernameLen > data.size()) return false;
    msg.username = std::string(data.begin() + pos, data.begin() + pos + usernameLen);
    pos += usernameLen;
    
    // 反序列化时间戳
    if (pos + sizeof(double) > data.size()) return false;
    msg.timestamp = *reinterpret_cast<const double*>(&data[pos]);
    pos += sizeof(double);
    
    // 反序列化消息内容
    if (pos + sizeof(uint32_t) > data.size()) return false;
    uint32_t contentLen = *reinterpret_cast<const uint32_t*>(&data[pos]);
    pos += sizeof(uint32_t);
    
    if (pos + contentLen > data.size()) return false;
    msg.content = std::string(data.begin() + pos, data.begin() + pos + contentLen);
    
    return true;
}

std::vector<uint8_t> serializeSystemMessage(const SystemMessage& msg) {
    std::vector<uint8_t> data;
    
    // 序列化消息长度和内容
    uint32_t msgLen = static_cast<uint32_t>(msg.content.length());
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&msgLen), 
               reinterpret_cast<const uint8_t*>(&msgLen) + sizeof(msgLen));
    data.insert(data.end(), msg.content.begin(), msg.content.end());
    
    return data;
}

bool deserializeSystemMessage(const std::vector<uint8_t>& data, SystemMessage& msg) {
    size_t pos = 0;
    
    // 反序列化消息
    if (pos + sizeof(uint32_t) > data.size()) return false;
    uint32_t msgLen = *reinterpret_cast<const uint32_t*>(&data[pos]);
    pos += sizeof(uint32_t);
    
    if (pos + msgLen > data.size()) return false;
    msg.content = std::string(data.begin() + pos, data.begin() + pos + msgLen);
    
    return true;
}

bool sendMessage(SOCKET s, uint8_t type, const std::vector<uint8_t>& data) {
    NetworkHeader header;
    header.type = type;
    header.length = sizeof(NetworkHeader) + data.size();
    
    // 先发送头部
    int bytesSent = send(s, reinterpret_cast<const char*>(&header), sizeof(NetworkHeader), 0);
    if (bytesSent != sizeof(NetworkHeader)) {
        return false;
    }
    
    // 再发送数据
    if (!data.empty()) {
        bytesSent = send(s, reinterpret_cast<const char*>(data.data()), data.size(), 0);
        if (bytesSent != static_cast<int>(data.size())) {
            return false;
        }
    }
    
    return true;
}
