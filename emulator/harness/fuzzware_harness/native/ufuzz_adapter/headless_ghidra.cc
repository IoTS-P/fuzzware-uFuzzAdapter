#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <chrono>
#include <filesystem>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <cstdlib> // Include the necessary header file
#include <nlohmann/json.hpp>

// Use nlohmann::json for JSON serialization
using json = nlohmann::json;
// namespace fs = std::filesystem;

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

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}


std::pair<std::vector<json>, json> run_ghidra_get_static_data(int port, unsigned long long callread_addr, unsigned long long read_addr, unsigned long long entry_point, unsigned long long irq_pc = 0, unsigned long long buffer_addr = 0, const std::string& dynamic_hook_indirect_path = "") {
    auto starttime = std::chrono::high_resolution_clock::now();

    std::vector<json> ghidra_script_type = {"global_static_data"};
    std::vector<json> ghidra_script_args = {callread_addr, read_addr, entry_point, irq_pc, buffer_addr, dynamic_hook_indirect_path};

    // Print ghidra_script_args in hex
    std::cout << "callread_addr,read_addr,irq_pc,entry_point,buffer_addr: [";
    for (size_t i = 0; i < ghidra_script_args.size() - 1; ++i) {
        std::cout << std::hex << ghidra_script_args[i] << (i < ghidra_script_args.size() - 2 ? ", " : "");
    }
    std::cout << "]" << std::endl;
    std::cout << "dynamic_hook_indirect_path: " << dynamic_hook_indirect_path << std::endl;

    ghidra_script_type.insert(ghidra_script_type.end(), ghidra_script_args.begin(), ghidra_script_args.end());

    json message = ghidra_script_type;
    json response = client_send_message(message, port);

    if (!response.is_array()) {
        std::cout << "the response is not list!" << std::endl;
        return {{}, {}};
    }

    if (response.size() == 1 && (!response[0].is_array() && !response[0].is_object())) {
        std::cout << "met the effective read point, got the effective data input pc = " << std::hex << response[0] << std::endl;
        return {response[0], {}};
    }

    // The return value of a static script is an array containing a dictionary
    // The last element of the array is the global traversal value
    std::vector<json> dt_dict_list = response;
    dt_dict_list.pop_back(); // Remove the last element
    json global_vars = response.back();

    auto endtime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = endtime - starttime;
    std::cout << "ghidra get read avail addr time: " << elapsed.count() << std::endl;
    std::cout << "ghidra get dt_dict_list: " << dt_dict_list << std::endl;
    std::cout << "ghidra get global_vars: " << global_vars << std::endl;
    return {dt_dict_list, global_vars};
}

json run_ghidra_get_callind_addr(int port) {
    auto starttime = std::chrono::high_resolution_clock::now();

    json ghidra_script_type = {"callind_collect"};
    json message = ghidra_script_type;
    json response = client_send_message(message, port);

    std::cout << "ghidra output: " << response << std::endl;

    auto endtime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = endtime - starttime;
    std::cout << "ghidra get callind addr time: " << elapsed.count() << std::endl;

    return response;
}



// int main() {
//     // Example usage:
//     std::string message = "Your message here";
//     int port = 11111;
//     std::string response = client_send_message(message, port);
//     std::cout << "Response: " << response << std::endl;

//     // Run Ghidra example
//     std::string binary_path = "/path/to/binary";
//     run_ghidra(binary_path, port);

//     return 0;
// }
