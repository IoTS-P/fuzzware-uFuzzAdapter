#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <jsoncpp/json/json.h> // Make sure to link against the JsonCpp library or include it in your project.

// Global logger function
void my_debug_log(const std::string& message) {
    std::ofstream log_file("/tmp/debug.log", std::ios::app);
    if (log_file.is_open()) {
        log_file << message << std::endl;
    }
}

// Function to handle each client connection
void handle_client(int client_socket) {
    try {
        while (true) {
            char buffer[1024] = {0};
            ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) {
                my_debug_log("Received but no data or error occurred");
                break;
            }

            std::string param_data(buffer);
            my_debug_log("Received: " + param_data);

            // Here you would parse the JSON and execute the corresponding function based on the run_type
            // For demonstration purposes, we'll just echo back the received data
            Json::Value root;
            Json::Reader reader;
            if (reader.parse(param_data, root)) {
                std::string run_type = root[0].asString();
                my_debug_log("run_type: " + run_type);

                // Execute the script based on run_type
                // ...

                // Send a response back to the client
                std::string response = "Response to " + run_type;
                send(client_socket, response.c_str(), response.length(), 0);
            } else {
                my_debug_log("JSON parsing error!");
                break;
            }
        }
    } catch (...) {
        my_debug_log("Error when receiving or handling data!");
    }
    close(client_socket);
    my_debug_log("Connection closed.");
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_address, client_address;
    socklen_t client_address_len = sizeof(client_address);

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        my_debug_log("Socket creation failed");
        return -1;
    }

    // Set socket options
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind socket to a port
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(10045); // Replace with your port number

    if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        my_debug_log("Socket bind failed");
        return -1;
    }

    // Listen for client connections
    listen(server_socket, 10);
    my_debug_log("Server is listening...");

    // Accept client connections and handle them in separate threads
    while (true) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_address, &client_address_len);
        if (client_socket < 0) {
            my_debug_log("Client accept failed");
            continue;
        }
        my_debug_log("Client connected");

        // Create a thread for each client
        std::thread client_thread(handle_client, client_socket);
        client_thread.detach(); // Detach the thread to handle independently
    }

    // Close the server socket
    close(server_socket);
    return 0;
}
