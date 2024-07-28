#include "dosbox.h"
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include "debug.h"


static inline uint32_t swap32(uint32_t x);
static inline uint16_t swap16(uint16_t x);

class GDBServer {
public:
    GDBServer(int port) : port(port), server_fd(-1), client_fd(-1) {}
    ~GDBServer() {
        if (client_fd != -1) close(client_fd);
        if (server_fd != -1) close(server_fd);
    }
    void run();
    void signal_breakpoint();

private:
    int port;
    int server_fd, client_fd;
    bool noack_mode = false;
    bool processing = false;

    void setup_socket();
    void wait_for_client();
    void handle_client();
    bool perform_handshake();
    std::string receive_packet();
    void send_packet(const std::string& packet);
    void process_command(const std::string& cmd);

    // GDB command handlers
    void handle_read_register(const std::string& cmd);
    void handle_read_registers();
    void handle_write_registers(const std::string& args);
    void handle_read_memory(const std::string& args);
    void handle_write_memory(const std::string& args);
    void handle_step();
    void handle_continue();
    void handle_breakpoint(const std::string& args);
    void handle_query(const std::string& args);
    void handle_v_packets(const std::string& cmd);

    // Helper functions
    std::string hex_encode(const std::string& input);
    std::string hex_decode(const std::string& input);
    uint8_t hex_to_int(char c);
};

