#include <iostream>
#include <mutex>
#include <queue>
#include "gdbserver.h"
#include "logging.h"

static std::queue<std::string> async_events;
static std::mutex async_mutex;

void queue_async_event(const std::string& event) {
    std::lock_guard<std::mutex> lock(async_mutex);
    async_events.push(event);
}

std::string get_next_async_event() {
    std::lock_guard<std::mutex> lock(async_mutex);
    if (async_events.empty()) return "";
    std::string event = async_events.front();
    async_events.pop();
    return event;
}

void GDBServer::run() {
    DEBUG_ShowMsg("About to start GDBServer");
    setup_socket();

    while (true) {
        wait_for_client();
        handle_client();
    }
}

void GDBServer::setup_socket() {
    struct sockaddr_in address;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        DEBUG_ShowMsg("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        DEBUG_ShowMsg("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        DEBUG_ShowMsg("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 1) < 0) {
        DEBUG_ShowMsg("listen");
        exit(EXIT_FAILURE);
    }

    DEBUG_ShowMsg("GDB server listening on port %d", port);
}

void GDBServer::wait_for_client() {
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    DEBUG_ShowMsg("Waiting for client connection...");
    if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        DEBUG_ShowMsg("accept");
        exit(EXIT_FAILURE);
    }
    DEBUG_ShowMsg("Client connected");
}

void GDBServer::handle_client() {
    DEBUG_ShowMsg("Handling client");

    // Perform initial handshake
    if (!perform_handshake()) {
        DEBUG_ShowMsg("Handshake failed");
        close(client_fd);
        return;
    }

    while (true) {
        std::string packet = receive_packet();
        //DEBUG_ShowMsg("GDB: Received packet %s", packet.c_str());
        if (packet.empty()) break;
        process_command(packet);

        // Check for async events even when not processing a packet
        std::string async_event = get_next_async_event();
        if (!async_event.empty()) {
            send_packet(async_event);
        }

    }

    close(client_fd);
}

bool GDBServer::perform_handshake() {
    std::string handshake = receive_packet();
    DEBUG_ShowMsg("Received handshake: %s", handshake.c_str());

    if (handshake.substr(0, 10) != "qSupported") {
        DEBUG_ShowMsg("Unexpected initial packet: %s", handshake.c_str());
        return false;
    }

    // Respond with supported features
    std::string response = "PacketSize=3fff;"
                           "swbreak+;"  // Software breakpoints
                           "hwbreak+;"  // Hardware breakpoints
                           "vContSupported+;" // vCont packet for continuing and stepping
                           "QStartNoAckMode+"; // no ack mode
    send_packet(response);
    DEBUG_ShowMsg("Sent supported features: %s", response.c_str());


    return true;
}


std::string GDBServer::receive_packet() {
    std::string packet;
    char c;

    // Wait for the start of the packet
    while (true) {
        if (read(client_fd, &c, 1) <= 0) {
            DEBUG_ShowMsg("Error reading from client or client disconnected");
            return "";
        }
        if (c == '$') break;
    }

    // Read the packet content
    while (true) {
        if (read(client_fd, &c, 1) <= 0) {
            DEBUG_ShowMsg("Error reading packet content");
            return "";
        }
        if (c == '#') break;
        packet += c;
    }

    // Read the checksum
    char checksum[2];
    if (read(client_fd, checksum, 2) <= 0) {
        DEBUG_ShowMsg("Error reading checksum");
        return "";
    }

    // Verify the checksum
    uint8_t received_checksum = (hex_to_int(checksum[0]) << 4) | hex_to_int(checksum[1]);
    uint8_t calculated_checksum = 0;
    for (char ch : packet) {
        calculated_checksum += ch;
    }

    if (received_checksum != calculated_checksum) {
        DEBUG_ShowMsg("Checksum mismatch: received 0x%02x, calculated 0x%02x", received_checksum, calculated_checksum);
        if (!noack_mode) {
            write(client_fd, "-", 1);
        }
        return "";
    }

    // Send acknowledgment if not in no-ack mode
    if (!noack_mode) {
        write(client_fd, "+", 1);
    }

    DEBUG_ShowMsg("<< %s", packet.c_str());

    return packet;
}

void GDBServer::send_packet(const std::string& packet) {
    DEBUG_ShowMsg(">> %s", packet.c_str());
    std::string response = "$" + packet + "#";
    uint8_t checksum = 0;
    for (char c : packet) {
        checksum += c;
    }
    char checksum_str[3];
    snprintf(checksum_str, sizeof(checksum_str), "%02x", checksum);
    response += checksum_str;

    write(client_fd, response.c_str(), response.length());

    if (!noack_mode) {
        // Wait for acknowledgment
        char ack;
        read(client_fd, &ack, 1);
    }
}

void GDBServer::signal_breakpoint() {
    if (processing) {
        queue_async_event("S05");
    } else {
        send_packet("S05");
    }

    //while (processing) {}
   // send_packet("S05");
}

void GDBServer::process_command(const std::string& cmd) {
    processing = true;
    DEBUG_ShowMsg("Processing command: %s", cmd.c_str());
    if(cmd == "QStartNoAckMode") {
        noack_mode = true;
        send_packet("OK");
    } else  if (cmd == "vMustReplyEmpty") {
        send_packet("");
    } else if (cmd == "?") {
        DEBUG_EnableDebugger();
        //send_packet("S05");  // Indicate a SIGTRAP
    } else if (cmd.substr(0, 1) == "H") {
        send_packet("OK");
        //handle_thread_select(cmd);
    } else if (cmd.substr(0, 1) == "p") {
        handle_read_register(cmd);
    } else if (cmd == "g") {
        handle_read_registers();
    } else if (cmd.substr(0, 1) == "G") {
        handle_write_registers(cmd.substr(1));
    } else if (cmd.substr(0, 1) == "m") {
        handle_read_memory(cmd.substr(1));
    } else if (cmd.substr(0, 1) == "M") {
        handle_write_memory(cmd.substr(1));
    } else if (cmd.substr(0, 1) == "Z" || cmd.substr(0, 1) == "z") {
        handle_breakpoint(cmd);
    } else if (cmd.substr(0, 1) == "s") {
        handle_step();
    } else if (cmd.substr(0, 1) == "c") {
        handle_continue();
    } else if (cmd.substr(0, 1) == "q") {
        handle_query(cmd.substr(1));
    } else if (cmd.substr(0, 4) == "vCont") {
        handle_v_packets(cmd.substr(5));
    } else {
        DEBUG_ShowMsg("Unhandled command: %s", cmd.c_str());
        send_packet("");
    }

    DEBUG_ShowMsg("Finished processing command: %s", cmd.c_str());
    processing = false;

    // After processing, check for any pending async events
    std::string async_event = get_next_async_event();
    if (!async_event.empty()) {
        send_packet(async_event);
    }

}

void GDBServer::handle_v_packets(const std::string& cmd) {
    if (cmd == "vCont?") {
        send_packet("vCont;c;s;t");
    } else if (cmd.substr(0, 5) == "vCont;") {
        // Handle vCont commands (continue, step, etc.)
        char action = cmd[6];
        switch (action) {
            case 'c':
                handle_continue();
                break;
            case 's':
                handle_step();
                break;
            default:
                send_packet("");
        }
    } else {
        send_packet("");
    }
}

void GDBServer::handle_read_register(const std::string& cmd) {
    int reg_num = std::stoi(cmd.substr(1), nullptr, 16);
    uint16_t value = DEBUG_GetRegister(reg_num);

    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(4) << value;
    std::string response = ss.str();

    // Reverse byte order if necessary (little-endian)
    std::swap(response[0], response[2]);
    std::swap(response[1], response[3]);

    send_packet(response);
}

void GDBServer::handle_read_registers() {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    // Assuming x86 32-bit register order: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, EIP, EFLAGS, CS, SS, DS, ES, FS, GS
    const int reg_count = 16;
    for (int i = 0; i < reg_count; ++i) {
        uint32_t value = DEBUG_GetRegister(i);
        ss << std::setw(8) << swap32(value);
    }

    send_packet(ss.str());
}

void GDBServer::handle_write_registers(const std::string& args) {
    std::stringstream ss(args);
    std::string reg_value;
    int reg_index = 0;

    while (std::getline(ss, reg_value, ',')) {
        if (reg_value.length() == 8) {
            uint32_t value = std::stoul(reg_value, nullptr, 16);
            DEBUG_SetRegister(reg_index, value);
        }
        reg_index++;
    }

    send_packet("OK");
}

void GDBServer::handle_read_memory(const std::string& args) {
    size_t comma = args.find(',');
    if (comma == std::string::npos) {
        send_packet("E01");
        return;
    }

    uint32_t address = std::stoul(args.substr(0, comma), nullptr, 16);
    uint32_t length = std::stoul(args.substr(comma + 1), nullptr, 16);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (uint32_t i = 0; i < length; ++i) {
        uint8_t value = DEBUG_ReadMemory(address + i);
        ss << std::setw(2) << static_cast<int>(value);
    }

    send_packet(ss.str());
}

void GDBServer::handle_write_memory(const std::string& args) {
    size_t comma = args.find(',');
    size_t colon = args.find(':');
    if (comma == std::string::npos || colon == std::string::npos) {
        send_packet("E01");
        return;
    }

    uint32_t address = std::stoul(args.substr(0, comma), nullptr, 16);
    uint32_t length = std::stoul(args.substr(comma + 1, colon - comma - 1), nullptr, 16);
    std::string data = hex_decode(args.substr(colon + 1));

    for (uint32_t i = 0; i < length && i < data.length(); ++i) {
        DEBUG_WriteMemory(address + i, data[i]);
    }

    send_packet("OK");
}

void GDBServer::handle_step() {
    DEBUG_Step();
    send_packet("S05");  // Assuming SIGTRAP as the stop reason
}

void GDBServer::handle_continue() {
    DEBUG_Continue();
    //send_packet("S05");  // Assuming SIGTRAP as the stop reason
}

void GDBServer::handle_breakpoint(const std::string& args) {
    char type = args[0];
    size_t comma1 = args.find(',');
    size_t comma2 = args.find(',', comma1 + 1);
    if (comma1 == std::string::npos || comma2 == std::string::npos) {
        send_packet("E01");
        return;
    }

    int bp_type = std::stoi(args.substr(1, comma1 - 1));
    uint32_t address = std::stoul(args.substr(comma1 + 1, comma2 - comma1 - 1), nullptr, 16);

    if (bp_type != 0) {  // We only support software breakpoints
        send_packet("");
        return;
    }

    bool success;
    if (type == 'Z') {
        success = DEBUG_SetBreakpoint(address);
    } else {
        success = DEBUG_RemoveBreakpoint(address);
    }

    send_packet(success ? "OK" : "E01");
}

void GDBServer::handle_query(const std::string& cmd) {
    if (cmd.substr(0, 14) == "Supported:") {
        send_packet("PacketSize=1000");
    } else if (cmd.substr(0, 11) == "fThreadInfo") {
        send_packet("m1");
    } else if(cmd.substr(0, 11) == "sThreadInfo") {
        send_packet("l");
    } else if(cmd.substr(0, 8) == "Attached") {
        send_packet("1");
    } else if (cmd == "C") {
        send_packet("");  // No current thread
    } else {
        send_packet("");  // Unsupported query
    }
}

std::string GDBServer::hex_encode(const std::string& input) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : input) {
        ss << std::setw(2) << static_cast<int>(c);
    }
    return ss.str();
}

std::string GDBServer::hex_decode(const std::string& input) {
    std::string output;
    for (size_t i = 0; i < input.length(); i += 2) {
        uint8_t byte = (hex_to_int(input[i]) << 4) | hex_to_int(input[i+1]);
        output.push_back(static_cast<char>(byte));
    }
    return output;
}

uint8_t GDBServer::hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static inline uint32_t swap32(uint32_t x) {
    return (((x >> 24) & 0x000000ff) |
            ((x >> 8) & 0x0000ff00) |
            ((x << 8) & 0x00ff0000) |
            ((x << 24) & 0xff000000));
}

static inline uint16_t swap16(uint16_t x) {
    return (x >> 8) | (x << 8);
}

