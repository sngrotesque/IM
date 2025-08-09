#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

void receiveMessages(SOCKET clientSocket) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(clientSocket, &readfds);
    timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;

    while (true) {
        fd_set tempFds = readfds;
        int result = select(static_cast<int>(clientSocket) + 1, &tempFds, nullptr, nullptr, &timeout);
        if (result == 0) {
            std::cout << "No data received in 30 seconds. Closing connection.\n";
            break;
        } else if (result == SOCKET_ERROR) {
            std::cerr << "select failed\n";
            break;
        }

        if (FD_ISSET(clientSocket, &tempFds)) {
            char buffer[1024];
            int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                std::cout << buffer << "\n";
            } else {
                std::cout << "Connection closed by server\n";
                break;
            }
        }
    }
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "socket failed\n";
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    if (connect(clientSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "connect failed\n";
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    std::string password;
    std::cout << "Enter password: ";
    std::cin >> password;
    send(clientSocket, password.c_str(), password.size(), 0);

    char authResponse[1024];
    int responseBytes = recv(clientSocket, authResponse, sizeof(authResponse) - 1, 0);
    if (responseBytes > 0) {
        authResponse[responseBytes] = '\0';
        if (strcmp(authResponse, "Authenticated") != 0) {
            std::cerr << "Authentication failed\n";
            closesocket(clientSocket);
            WSACleanup();
            return 1;
        }
    } else {
        std::cerr << "Failed to receive authentication response\n";
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    std::string username;
    std::cout << "Enter your username: ";
    std::cin >> username;

    std::thread receiver(receiveMessages, clientSocket);
    receiver.detach();

    while (true) {
        std::string message;
        std::getline(std::cin, message);
        if (message == "exit") break;

        using namespace std::chrono;
        high_resolution_clock::time_point now = high_resolution_clock::now();
        duration<double> elapsed = now.time_since_epoch();
        double timestamp = elapsed.count();

        std::ostringstream oss;
        oss << std::fixed << std::setprecision(6) << timestamp;
        std::string timestampStr = oss.str();

        std::string fullMessage = timestampStr + " " + message;
        uint32_t messageLength = static_cast<uint32_t>(fullMessage.size());

        char buffer[sizeof(uint32_t) + fullMessage.size()];
        memcpy(buffer, &messageLength, sizeof(uint32_t));
        memcpy(buffer + sizeof(uint32_t), fullMessage.c_str(), fullMessage.size());

        send(clientSocket, buffer, sizeof(buffer), 0);
    }

    closesocket(clientSocket);
    WSACleanup();

    return 0;
}
