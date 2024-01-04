#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>
#include <filesystem>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <signal.h>
#include <netdb.h>

namespace fs = std::filesystem;

void my_debug_log(const std::string& message) {
    std::cout << message << std::endl;
}

std::string client_send_message(const std::string& message, int port) {
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        my_debug_log("Socket creation error");
        return "";
    }

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");

    int res = -1;
    while (true) {
        res = connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address));
        if (res == 0) {
            my_debug_log("Connection successful!");
            break;
        } else {
            my_debug_log("Server may not be ready yet, wait and try again");
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
    }

    send(client_socket, message.c_str(), message.length(), 0);

    char buffer[8192];
    std::memset(buffer, 0, sizeof(buffer));
    int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received < 0) {
        my_debug_log("Receive error");
        close(client_socket);
        return "";
    }

    std::string response(buffer);
    my_debug_log("Received: " + response);

    close(client_socket);
    return response;
}

void run_ghidra(const std::string& binary, int port) {
    // Create ghidra project
    std::string home_dir = getenv("HOME");
    std::string project_path = home_dir + "/ghidra_project";
    fs::create_directories(project_path);

    my_debug_log("Current port is: " + std::to_string(port));

    // Check if another program is occupying the port
    std::string cmd1 = "netstat -tulnp | grep :" + std::to_string(port) + " | awk '{print $7}'";
    std::string result1 = exec(cmd1.c_str());
    // Process result1 to check if the port is occupied and by which process

    // Run Ghidra if necessary
    my_debug_log("Run new ghidra server");
    // Construct the command to run Ghidra headless and execute it
}

int main() {
    // Example usage:
    std::string message = "Your message here";
    int port = 11111;
    std::string response = client_send_message(message, port);
    std::cout << "Response: " << response << std::endl;

    // Run Ghidra example
    std::string binary_path = "/path/to/binary";
    run_ghidra(binary_path, port);

    return 0;
}
