/*
 *  TTY server -- telnet bridge onto the emulated character console.
 *
 *  See include/ttyserver.h for what this does. The networking lives in its own
 *  thread; it never touches emulator state directly. Two queues guarded by one
 *  mutex connect it to the emulation thread:
 *
 *    out_queue  emulation thread appends characters (TTYSERVER_CharOut),
 *               the network thread drains them to every connected client.
 *    in_queue   network thread appends decoded BIOS key words, the emulation
 *               thread drains them from a timer tick handler.
 */

#if defined(WIN32)
/* before dosbox.h, which may drag in the older winsock.h through windows.h */
# include <winsock2.h>
# include <ws2tcpip.h>
#endif

#include "config.h"

#include "dosbox.h"
#include "logging.h"
#include "setup.h"
#include "control.h"
#include "timer.h"
#include "bios.h"
#include "ttyserver.h"

#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <thread>

#if defined(WIN32)
typedef SOCKET tty_socket_t;
# define TTY_INVALID_SOCKET  INVALID_SOCKET
# define tty_closesocket(s)  closesocket(s)
# define tty_sockerr()       WSAGetLastError()
# define TTY_EWOULDBLOCK     WSAEWOULDBLOCK
typedef int tty_socklen_t;
#else
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <arpa/inet.h>
# include <unistd.h>
# include <fcntl.h>
# include <errno.h>
typedef int tty_socket_t;
# define TTY_INVALID_SOCKET  (-1)
# define tty_closesocket(s)  close(s)
# define tty_sockerr()       errno
# define TTY_EWOULDBLOCK     EWOULDBLOCK
typedef socklen_t tty_socklen_t;
#endif

/* telnet protocol bytes we care about (RFC 854/857/858) */
#define TEL_SE      240
#define TEL_SB      250
#define TEL_WILL    251
#define TEL_WONT    252
#define TEL_DO      253
#define TEL_DONT    254
#define TEL_IAC     255
#define TELOPT_ECHO          1
#define TELOPT_SUPPRESS_GA   3

/* how long a lone ESC waits for the rest of a sequence before it is taken to be
 * the ESC key itself */
#define TTY_ESC_TIMEOUT_MS   50

/* the select() timeout, and therefore the worst case output latency */
#define TTY_POLL_MS          10

/* per client send backlog before we give up on that client */
#define TTY_MAX_PENDING      (1u<<20)

/* characters buffered for clients that have fallen behind */
#define TTY_MAX_OUTQUEUE     (256u*1024u)

/* ------------------------------------------------------------------------- */
/* shared state                                                              */
/* ------------------------------------------------------------------------- */

static std::mutex            tty_mutex;
static std::string           tty_out_queue;      /* guest -> clients */
static std::deque<uint16_t>  tty_in_queue;       /* clients -> guest, BIOS key words */
static bool                  tty_have_client = false;
static uint8_t               tty_last_out = 0;   /* survives the queue being drained */

static std::thread           tty_thread;
static volatile bool         tty_thread_quit = false;
static volatile bool         tty_running = false;

/* configuration, read once at startup */
static int          tty_port = 2160;
static std::string  tty_bindaddress = "127.0.0.1";
static bool         tty_telnet = true;
static bool         tty_crlf = true;

/* suppression depth, emulation thread only */
static int          tty_suppress_depth = 0;

TTYServerSuppress::TTYServerSuppress() { tty_suppress_depth++; }
TTYServerSuppress::~TTYServerSuppress() { tty_suppress_depth--; }

/* ------------------------------------------------------------------------- */
/* guest -> client                                                           */
/* ------------------------------------------------------------------------- */

void TTYSERVER_CharOut(uint8_t chr) {
    if (!tty_running || tty_suppress_depth != 0) return;

    std::lock_guard<std::mutex> lock(tty_mutex);

    /* nobody listening: drop it rather than grow without bound */
    if (!tty_have_client) return;
    if (tty_out_queue.size() >= TTY_MAX_OUTQUEUE) return;

    if (tty_crlf && chr == '\n' && tty_last_out != '\r')
        tty_out_queue += '\r';

    tty_out_queue += (char)chr;
    tty_last_out = chr;

    /* 0xFF is IAC on the wire and has to be doubled to come out as data */
    if (tty_telnet && chr == 0xFF) tty_out_queue += (char)0xFF;
}

/* ------------------------------------------------------------------------- */
/* client -> guest: key translation                                          */
/* ------------------------------------------------------------------------- */

/* scan codes of the extended keys, ASCII part is zero for all of them */
#define SC_F1       0x3B
#define SC_F11      0x85
#define SC_F12      0x86
#define SC_HOME     0x47
#define SC_UP       0x48
#define SC_PGUP     0x49
#define SC_LEFT     0x4B
#define SC_RIGHT    0x4D
#define SC_END      0x4F
#define SC_DOWN     0x50
#define SC_PGDN     0x51
#define SC_INS      0x52
#define SC_DEL      0x53

/* Map a plain byte to a BIOS key word (scan code in the high half, ASCII in the
 * low half). Printable characters get scan code 0, which is what DOSBox-X's own
 * clipboard paste uses and what INT 16h consumers read AL from. */
static uint16_t tty_ascii_to_key(uint8_t c) {
    /* scan codes of 'a'..'z', used to give Ctrl+letter a plausible scan code */
    static const uint8_t ctrl_scan[26] = {
        0x1E,0x30,0x2E,0x20,0x12,0x21,0x22,0x23,0x17,0x24,0x25,0x26,0x32,
        0x31,0x18,0x19,0x10,0x13,0x1F,0x14,0x16,0x2F,0x11,0x2D,0x15,0x2C
    };

    switch (c) {
        case 0x08: return 0x0E08;   /* backspace */
        case 0x09: return 0x0F09;   /* tab */
        case 0x0D: return 0x1C0D;   /* enter */
        case 0x1B: return 0x011B;   /* escape */
        case 0x7F: return 0x0E08;   /* terminals send DEL for the backspace key */
        default: break;
    }

    if (c >= 1 && c <= 26) return (uint16_t)((ctrl_scan[c-1] << 8) | c);
    if (c >= 0x20) return (uint16_t)c;
    return 0;
}

/* final byte of a CSI sequence with no numeric parameter, e.g. ESC [ A */
static uint16_t tty_csi_letter_to_key(char final_byte) {
    switch (final_byte) {
        case 'A': return SC_UP    << 8;
        case 'B': return SC_DOWN  << 8;
        case 'C': return SC_RIGHT << 8;
        case 'D': return SC_LEFT  << 8;
        case 'H': return SC_HOME  << 8;
        case 'F': return SC_END   << 8;
        default:  return 0;
    }
}

/* ESC [ <n> ~ */
static uint16_t tty_csi_tilde_to_key(int n) {
    switch (n) {
        case 1:  case 7:  return SC_HOME << 8;
        case 2:           return SC_INS  << 8;
        case 3:           return SC_DEL  << 8;
        case 4:  case 8:  return SC_END  << 8;
        case 5:           return SC_PGUP << 8;
        case 6:           return SC_PGDN << 8;
        case 11: case 12: case 13: case 14: case 15:
            return (uint16_t)((SC_F1 + (n - 11)) << 8);                 /* F1..F5  */
        case 17: case 18: case 19: case 20: case 21:
            return (uint16_t)((SC_F1 + 5 + (n - 17)) << 8);             /* F6..F10 */
        case 23:          return SC_F11 << 8;
        case 24:          return SC_F12 << 8;
        default:          return 0;
    }
}

/* ESC O P..S */
static uint16_t tty_ss3_to_key(char c) {
    if (c >= 'P' && c <= 'S') return (uint16_t)((SC_F1 + (c - 'P')) << 8);
    return tty_csi_letter_to_key(c);   /* some terminals send ESC O A for Up */
}

/* ------------------------------------------------------------------------- */
/* client state                                                              */
/* ------------------------------------------------------------------------- */

enum TelnetState { TS_DATA, TS_IAC, TS_OPTION, TS_SB, TS_SB_IAC };
enum KeyState    { KS_NORMAL, KS_ESC, KS_CSI, KS_SS3 };

struct TTYClient {
    tty_socket_t fd;
    std::string  pending;          /* not yet written to the socket */

    TelnetState  tstate;
    KeyState     kstate;
    std::string  csi;              /* CSI parameter bytes collected so far */
    uint32_t     esc_time;         /* GetTicks() when the lone ESC arrived */
    bool         eat_after_cr;     /* swallow the LF or NUL that follows a CR */

    TTYClient(tty_socket_t s) :
        fd(s), tstate(TS_DATA), kstate(KS_NORMAL), esc_time(0), eat_after_cr(false) {}
};

static void tty_push_key(uint16_t key) {
    if (key == 0) return;
    std::lock_guard<std::mutex> lock(tty_mutex);
    if (tty_in_queue.size() < 256) tty_in_queue.push_back(key);
}

/* Feed one post-telnet byte through the VT sequence decoder. */
static void tty_decode_byte(TTYClient &cl, uint8_t c) {
    switch (cl.kstate) {
    case KS_NORMAL:
        if (c == 0x1B) {
            cl.kstate = KS_ESC;
            cl.esc_time = GetTicks();
            cl.eat_after_cr = false;
            return;
        }
        if (cl.eat_after_cr) {
            cl.eat_after_cr = false;
            if (c == '\n' || c == 0) return;    /* tail of a CR LF / CR NUL pair */
        }
        if (c == '\r') {
            cl.eat_after_cr = true;
            tty_push_key(0x1C0D);
            return;
        }
        if (c == '\n') { tty_push_key(0x1C0D); return; }
        if (c == 0) return;
        tty_push_key(tty_ascii_to_key(c));
        return;

    case KS_ESC:
        if (c == '[')      { cl.kstate = KS_CSI; cl.csi.clear(); return; }
        if (c == 'O')      { cl.kstate = KS_SS3; return; }
        if (c == 0x1B)     { tty_push_key(0x011B); cl.esc_time = GetTicks(); return; }
        /* anything else: a bare ESC followed by that byte */
        tty_push_key(0x011B);
        cl.kstate = KS_NORMAL;
        tty_decode_byte(cl, c);
        return;

    case KS_CSI:
        if (c >= 0x40 && c <= 0x7E) {           /* final byte */
            if (c == '~') {
                int n = cl.csi.empty() ? 0 : atoi(cl.csi.c_str());
                tty_push_key(tty_csi_tilde_to_key(n));
            }
            else {
                tty_push_key(tty_csi_letter_to_key((char)c));
            }
            cl.kstate = KS_NORMAL;
            return;
        }
        if (cl.csi.size() < 16) cl.csi += (char)c;
        return;

    case KS_SS3:
        tty_push_key(tty_ss3_to_key((char)c));
        cl.kstate = KS_NORMAL;
        return;
    }
}

/* Strip telnet negotiation, then hand the data bytes to the VT decoder. */
static void tty_feed(TTYClient &cl, const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t c = buf[i];

        if (!tty_telnet) { tty_decode_byte(cl, c); continue; }

        switch (cl.tstate) {
        case TS_DATA:
            if (c == TEL_IAC) cl.tstate = TS_IAC;
            else tty_decode_byte(cl, c);
            break;
        case TS_IAC:
            if (c == TEL_IAC) { cl.tstate = TS_DATA; tty_decode_byte(cl, 0xFF); }
            else if (c == TEL_WILL || c == TEL_WONT || c == TEL_DO || c == TEL_DONT)
                cl.tstate = TS_OPTION;      /* refuse silently: ignore the option byte */
            else if (c == TEL_SB) cl.tstate = TS_SB;
            else cl.tstate = TS_DATA;       /* a two byte command, nothing to do */
            break;
        case TS_OPTION:
            cl.tstate = TS_DATA;
            break;
        case TS_SB:
            if (c == TEL_IAC) cl.tstate = TS_SB_IAC;
            break;
        case TS_SB_IAC:
            cl.tstate = (c == TEL_SE) ? TS_DATA : TS_SB;
            break;
        }
    }
}

/* ------------------------------------------------------------------------- */
/* network thread                                                            */
/* ------------------------------------------------------------------------- */

static void tty_set_nonblocking(tty_socket_t s) {
#if defined(WIN32)
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif
}

static tty_socket_t tty_listen(void) {
    struct sockaddr_in addr;
    tty_socket_t s;
    int opt = 1;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == TTY_INVALID_SOCKET) {
        LOG_MSG("TTY server: cannot create socket (error %d)", tty_sockerr());
        return TTY_INVALID_SOCKET;
    }

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)tty_port);
    if (tty_bindaddress.empty() || tty_bindaddress == "any")
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else
        addr.sin_addr.s_addr = inet_addr(tty_bindaddress.c_str());

    if (addr.sin_addr.s_addr == INADDR_NONE) {
        LOG_MSG("TTY server: bad bindaddress '%s'", tty_bindaddress.c_str());
        tty_closesocket(s);
        return TTY_INVALID_SOCKET;
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        LOG_MSG("TTY server: cannot bind %s:%d (error %d)",
                tty_bindaddress.c_str(), tty_port, tty_sockerr());
        tty_closesocket(s);
        return TTY_INVALID_SOCKET;
    }

    if (listen(s, 4) != 0) {
        LOG_MSG("TTY server: cannot listen (error %d)", tty_sockerr());
        tty_closesocket(s);
        return TTY_INVALID_SOCKET;
    }

    tty_set_nonblocking(s);
    LOG_MSG("TTY server: listening on %s:%d", tty_bindaddress.c_str(), tty_port);
    return s;
}

/* Ask the client for character-at-a-time mode, which is what makes a telnet
 * session behave like a terminal attached to the guest. */
static void tty_send_negotiation(TTYClient &cl) {
    static const uint8_t greeting[] = {
        TEL_IAC, TEL_WILL, TELOPT_ECHO,          /* we echo (the guest does) */
        TEL_IAC, TEL_WILL, TELOPT_SUPPRESS_GA,
        TEL_IAC, TEL_DO,   TELOPT_SUPPRESS_GA
    };
    cl.pending.append((const char*)greeting, sizeof(greeting));
}

/* Returns false when the client should be dropped. */
static bool tty_flush(TTYClient &cl) {
    while (!cl.pending.empty()) {
        int n = (int)send(cl.fd, cl.pending.data(), (int)cl.pending.size(), 0);
        if (n > 0) { cl.pending.erase(0, (size_t)n); continue; }
        if (n == 0) return false;
        if (tty_sockerr() == TTY_EWOULDBLOCK) break;
        return false;
    }
    return cl.pending.size() < TTY_MAX_PENDING;
}

static void tty_thread_func(void) {
    tty_socket_t listen_fd = tty_listen();
    std::vector<TTYClient> clients;

    /* NTS: on failure just return. tty_running stays set so that shutdown still
     * joins this thread; with no listener nothing is ever captured anyway. */
    if (listen_fd == TTY_INVALID_SOCKET) return;

    while (!tty_thread_quit) {
        fd_set rfds;
        struct timeval tv;
        tty_socket_t maxfd = listen_fd;

        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        for (size_t i = 0; i < clients.size(); i++) {
            FD_SET(clients[i].fd, &rfds);
            if (clients[i].fd > maxfd) maxfd = clients[i].fd;
        }

        tv.tv_sec = 0;
        tv.tv_usec = TTY_POLL_MS * 1000;
        if (select((int)maxfd + 1, &rfds, NULL, NULL, &tv) < 0) {
            if (tty_sockerr() == TTY_EWOULDBLOCK) continue;
#if !defined(WIN32)
            if (tty_sockerr() == EINTR) continue;
#endif
            break;
        }

        /* new connections */
        if (FD_ISSET(listen_fd, &rfds)) {
            struct sockaddr_in peer;
            tty_socklen_t peerlen = sizeof(peer);
            tty_socket_t c = accept(listen_fd, (struct sockaddr*)&peer, &peerlen);
            if (c != TTY_INVALID_SOCKET) {
                int one = 1;
                tty_set_nonblocking(c);
                setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
                clients.push_back(TTYClient(c));
                if (tty_telnet) tty_send_negotiation(clients.back());
                LOG_MSG("TTY server: client connected from %s", inet_ntoa(peer.sin_addr));
            }
        }

        /* incoming data */
        for (size_t i = 0; i < clients.size(); ) {
            bool drop = false;

            if (FD_ISSET(clients[i].fd, &rfds)) {
                uint8_t buf[512];
                int n = (int)recv(clients[i].fd, (char*)buf, sizeof(buf), 0);
                if (n > 0) tty_feed(clients[i], buf, (size_t)n);
                else if (n == 0) drop = true;
                else if (tty_sockerr() != TTY_EWOULDBLOCK) drop = true;
            }

            /* a lone ESC that nothing completed is the ESC key */
            if (!drop && clients[i].kstate == KS_ESC &&
                (GetTicks() - clients[i].esc_time) > TTY_ESC_TIMEOUT_MS) {
                clients[i].kstate = KS_NORMAL;
                tty_push_key(0x011B);
            }

            if (drop) {
                LOG_MSG("TTY server: client disconnected");
                tty_closesocket(clients[i].fd);
                clients.erase(clients.begin() + (ptrdiff_t)i);
            }
            else i++;
        }

        /* guest output -> every client */
        {
            std::string out;
            {
                std::lock_guard<std::mutex> lock(tty_mutex);
                tty_have_client = !clients.empty();
                out.swap(tty_out_queue);
            }
            if (!out.empty())
                for (size_t i = 0; i < clients.size(); i++) clients[i].pending += out;
        }

        for (size_t i = 0; i < clients.size(); ) {
            if (!tty_flush(clients[i])) {
                LOG_MSG("TTY server: dropping client");
                tty_closesocket(clients[i].fd);
                clients.erase(clients.begin() + (ptrdiff_t)i);
            }
            else i++;
        }
    }

    for (size_t i = 0; i < clients.size(); i++) tty_closesocket(clients[i].fd);
    tty_closesocket(listen_fd);
}

/* ------------------------------------------------------------------------- */
/* emulation side                                                            */
/* ------------------------------------------------------------------------- */

/* Runs on the emulation thread once per millisecond. One key per tick keeps the
 * 15 entry BIOS buffer from overflowing and reads like fast but human typing. */
static void TTYSERVER_TickHandler(void) {
    uint16_t key;

    {
        std::lock_guard<std::mutex> lock(tty_mutex);
        if (tty_in_queue.empty()) return;
        key = tty_in_queue.front();
    }

    if (BIOS_AddKeyToBuffer(key)) {
        std::lock_guard<std::mutex> lock(tty_mutex);
        if (!tty_in_queue.empty()) tty_in_queue.pop_front();
    }
    /* else: guest buffer full, try again next tick */
}

static void TTYSERVER_ShutDown(Section *sec) {
    (void)sec;
    if (!tty_running) return;

    tty_running = false;
    tty_thread_quit = true;
    TIMER_DelTickHandler(&TTYSERVER_TickHandler);
    if (tty_thread.joinable()) tty_thread.join();

    std::lock_guard<std::mutex> lock(tty_mutex);
    tty_out_queue.clear();
    tty_in_queue.clear();
    tty_have_client = false;
    tty_last_out = 0;
}

void TTYSERVER_Init(void) {
    Section_prop *section = static_cast<Section_prop*>(control->GetSection("ttyserver"));
    if (section == NULL) return;
    if (!section->Get_bool("ttyserver")) return;

    LOG(LOG_MISC, LOG_DEBUG)("Initializing TTY (telnet) server");

    tty_port = section->Get_int("port");
    tty_bindaddress = section->Get_string("bindaddress");
    tty_telnet = section->Get_bool("telnet");
    tty_crlf = section->Get_bool("crlf");

    if (tty_port <= 0 || tty_port > 65535) {
        LOG_MSG("TTY server: port %d out of range, not starting", tty_port);
        return;
    }

#if defined(WIN32)
    {
        /* refcounted; SDL_net and the serial port code may have started it already */
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
            LOG_MSG("TTY server: WSAStartup failed, not starting");
            return;
        }
    }
#endif

    tty_thread_quit = false;
    tty_running = true;
    tty_thread = std::thread(tty_thread_func);

    TIMER_AddTickHandler(&TTYSERVER_TickHandler);
    AddExitFunction(AddExitFunctionFuncPair(TTYSERVER_ShutDown), true);
}
