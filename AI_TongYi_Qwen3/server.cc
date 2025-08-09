#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <map>
#include <ctime>
#include <openssl/evp.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libeay32.lib")

struct ClientInfo {
    std::string username;
    sockaddr_in address;
};

bool authenticate(const std::string& password) {
    // Example hashed password for user 'admin': 'password123'
    const char* expectedHash = "d2c7e9f8a05fe9b4d3bf5ee3698fdbeccf571ad6";
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    if (1 != EVP_DigestUpdate(mdctx, password.c_str(), password.size())) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hashLen)) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    EVP_MD_CTX_free(mdctx);

    std::string computedHash(reinterpret_cast<char*>(hash), hashLen);
    return computedHash == expectedHash;
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "socket failed\n";
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(12345);

    if (bind(serverSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "bind failed\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "listen failed\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    fd_set masterSet;
    FD_ZERO(&masterSet);
    FD_SET(serverSocket, &masterSet);
    SOCKET maxSocket = serverSocket;

    std::map<SOCKET, ClientInfo> clients;
    time_t lastActivityTime = time(NULL);

    while (true) {
        fd_set workingSet = masterSet;
        timeval timeout;
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;

        int selectResult = select(static_cast<int>(maxSocket + 1), &workingSet, nullptr, nullptr, &timeout);
        if (selectResult == 0) {
            if (difftime(time(NULL), lastActivityTime) >= 30 && clients.empty()) {
                break; // No activity for 30 seconds and no clients connected
            }
            continue;
        } else if (selectResult == SOCKET_ERROR) {
            std::cerr << "select failed\n";
            break;
        }

        for (SOCKET sock = 0; sock <= maxSocket; ++sock) {
            if (FD_ISSET(sock, &workingSet)) {
                if (sock == serverSocket) {
                    sockaddr_in clientAddr;
                    int addrSize = sizeof(clientAddr);
                    SOCKET newClient = accept(serverSocket, (SOCKADDR*)&clientAddr, &addrSize);
                    if (newClient == INVALID_SOCKET) {
                        std::cerr << "accept failed\n";
                        continue;
                    }

                    FD_SET(newClient, &masterSet);
                    if (newClient > maxSocket) maxSocket = newClient;

                    std::cout << "New connection from " << inet_ntoa(clientAddr.sin_addr) << ":" << ntohs(clientAddr.sin_port) << "\n";

                    // Authenticate the client
                    char buffer[1024];
                    int bytesReceived = recv(newClient, buffer, sizeof(buffer) - 1, 0);
                    if (bytesReceived > 0) {
                        buffer[bytesReceived] = '\0';
                        std::string password(buffer);
                        if (authenticate(password)) {
                            send(newClient, "Authenticated", 13, 0);
                            clients[newClient].address = clientAddr;
                        } else {
                            send(newClient, "Authentication Failed", 20, 0);
                            closesocket(newClient);
                            FD_CLR(newClient, &masterSet);
                        }
                    } else {
                        closesocket(newClient);
                        FD_CLR(newClient, &masterSet);
                    }
                } else {
                    char buffer[1024];
                    int bytesRead = recv(sock, buffer, sizeof(buffer), 0);
                    if (bytesRead > 0) {
                        uint32_t messageLength;
                        memcpy(&messageLength, buffer, sizeof(messageLength));
                        std::string message(buffer + sizeof(messageLength), messageLength);

                        // Extract timestamp and message content
                        size_t delimiterPos = message.find(' ');
                        double timestamp = std::stod(message.substr(0, delimiterPos));
                        std::string actualMessage = message.substr(delimiterPos + 1);

                        // Broadcast the message to all other clients
                        std::string ipAddress = inet_ntoa(clients[sock].address.sin_addr);
                        std::string port = std::to_string(ntohs(clients[sock].address.sin_port));
                        std::string displayMessage = "Client [" + clients[sock].username + "] [" + ipAddress + ":" + port + "] [" + std::to_string(timestamp) + "]: " + actualMessage;

                        std::cout << displayMessage << "\n";

                        std::string broadcastMessage = "Client [" + clients[sock].username + "] [" + std::to_string(timestamp) + "]: " + actualMessage;
                        for (const auto& pair : clients) {
                            if (pair.first != sock) {
                                send(pair.first, broadcastMessage.c_str(), broadcastMessage.size(), 0);
                            }
                        }

                        lastActivityTime = time(NULL);
                    } else {
                        closesocket(sock);
                        FD_CLR(sock, &masterSet);
                        clients.erase(sock);
                    }
                }
            }
        }
    }

    for (const auto& pair : clients) {
        closesocket(pair.first);
    }
    closesocket(serverSocket);
    WSACleanup();

    return 0;
}
