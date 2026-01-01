// ip2uart.c — TTY/STDIO <-> UDP bridge for embedded Linux
// - UART side selectable: uart_backend=tty | stdio
// - UDP: static peer (fire-and-forget), accepts from any sender
// - UDP coalescing: size threshold + short idle before send
// - Short-write safe: ring buffers for both directions (non-blocking)
// - SIGHUP: reload /etc/ip2uart.conf and reopen resources
// - Verbose logging: -v prints one-line stats once per second
// autod – Autod Personal Use License
// Copyright (c) 2025 Joakim Snökvist
// Licensed for personal, non-commercial use only.
// Redistribution or commercial use requires prior written approval from Joakim Snökvist.
// See LICENSE.md for full terms.
//

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#if defined(__linux__)
#include <asm/ioctls.h>
#define termios asm_termios
#include <asm/termbits.h>
#undef termios
#endif
#include <time.h>
#include <unistd.h>

#define DEFAULT_CONF "/etc/ip2uart.conf"
#define MAX_LINE     512
#define MAX_KEY      64
#define MAX_VAL      256
#define MAX_EVENTS   18

typedef enum { UART_TTY, UART_STDIO } uart_backend_t;

/* ----------------------------- Verbose logging ------------------------------ */
static int g_verbosity = 0;

static long long ts_ms_now(void){
    struct timespec rt; clock_gettime(CLOCK_REALTIME, &rt);
    return (long long)rt.tv_sec*1000LL + rt.tv_nsec/1000000LL;
}
static void vlog(int level, const char *fmt, ...){
    if (g_verbosity < level) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[%lld] ", ts_ms_now());
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/* ----------------- Small ring buffer (non-blocking IO helper) ----------------- */
typedef struct { uint8_t *buf; size_t cap, head, tail, len; } ringbuf_t;
static int    ring_init (ringbuf_t *r, size_t cap){
    r->buf=NULL; r->cap=r->head=r->tail=r->len=0;
    if(!cap) return 0;
    r->buf=(uint8_t*)malloc(cap);
    if(!r->buf){ errno=ENOMEM; return -1; }
    r->cap=cap;
    return 0;
}
static void   ring_free (ringbuf_t *r){ free(r->buf); r->buf=NULL; r->cap=r->head=r->tail=r->len=0; }
static size_t ring_space(const ringbuf_t *r){ return r->cap - r->len; }
static size_t ring_write(ringbuf_t *r, const uint8_t *src, size_t n){
    if (!r->cap || !n) return 0;
    size_t w = n>ring_space(r)?ring_space(r):n;
    size_t first = w>(r->cap-r->head) ? (r->cap-r->head) : w;
    if (first) memcpy(r->buf + r->head, src, first);
    size_t second = w - first;
    if (second) memcpy(r->buf, src + first, second);
    r->head = (r->head + w) % r->cap; r->len += w;
    return w;
}
static size_t ring_peek(const ringbuf_t *r, const uint8_t **p1, size_t *l1, const uint8_t **p2, size_t *l2){
    if (!r->len){ *p1=*p2=NULL; *l1=*l2=0; return 0; }
    size_t first = r->len>(r->cap-r->tail) ? (r->cap-r->tail) : r->len;
    *p1 = r->buf + r->tail; *l1 = first; *p2 = NULL; *l2 = 0;
    if (r->len > first){ *p2 = r->buf; *l2 = r->len - first; }
    return r->len;
}
static void ring_consume(ringbuf_t *r, size_t n){ if (n>r->len) n=r->len; r->tail=(r->tail+n)%r->cap; r->len-=n; }

/* --------------------------------- Config ----------------------------------- */
typedef enum {
    PROTO_OFF = 0,
    PROTO_CRSF,
    PROTO_MSP,
    PROTO_MAV
} config_proto_t;

typedef struct {
    // Selectors
    uart_backend_t uart_backend;   // tty | stdio

    // Telemetry parsers
    config_proto_t telemetry_proto; // off|auto|crsf|msp|mavlink
    int  telemetry_log_enable;      // 0 | 1
    char telemetry_log_path[256];
    int  telemetry_log_interval;    // >= 0
    int  telemetry_coalesce;        // 0 | 1
    int  telemetry_msp_rate;        // Hz, default 5

    // UART
    char uart_device[128];
    int  uart_baud;
    int  uart_databits;    // 5..8
    char uart_parity[8];   // none|even|odd
    int  uart_stopbits;    // 1|2
    char uart_flow[16];    // none|rtscts

    // UDP static
    char udp_bind_addr[64];
    int  udp_bind_port;
    char udp_peer_addr[64];
    int  udp_peer_port;

    // UDP coalescing
    int  udp_coalesce_bytes;   // send immediately if >=
    int  udp_coalesce_idle_ms; // or if idle for this long
    int  udp_max_datagram;     // max size of one datagram

    // Buffers
    size_t rx_buf; // scratch RX buffers
    size_t tx_buf; // ring buffer capacity
} config_t;

/* ------------------------------ CRSF monitor ------------------------------- */
typedef enum { CRSF_FROM_UART = 0, CRSF_FROM_UDP = 1, CRSF_SRC_MAX = 2 } crsf_source_t;

typedef void (*crsf_frame_handler_t)(crsf_source_t src, uint8_t type,
                                     const uint8_t *payload, size_t payload_len,
                                     void *user);

typedef struct {
    uint8_t frame[256];
    size_t len;
    size_t expected;
} crsf_stream_t;

typedef struct {
    bool enabled;
    bool recognized_types[256];
    bool unknown_reported[256];
    crsf_stream_t streams[CRSF_SRC_MAX];
    uint64_t type_counts[CRSF_SRC_MAX][256];
    uint64_t invalid_frames[CRSF_SRC_MAX];
    struct timespec last_report;
    crsf_frame_handler_t on_frame;
    void *on_frame_user;
} crsf_monitor_t;

typedef struct {
    bool has_battery;
    bool has_gps;
    bool has_status;
    bool has_baro;
    bool has_home;
    bool has_any;

    double voltage_v;
    double current_raw;
    uint32_t capacity_mah;
    uint8_t remaining_pct;

    double latitude_deg;
    double longitude_deg;
    double groundspeed_raw;
    double heading_deg;
    double altitude_m;
    uint8_t sats;

    bool armed;
    bool has_attitude;
    uint32_t flight_mode_flags;
    uint16_t rssi_raw;

    double roll_deg;
    double pitch_deg;

    double baro_altitude_m;
    double vario_m_s;

    double home_dist_m;
    double home_dir_deg;

    bool prev_armed;
    double armed_start_time;
    double armed_accumulated_s;

    uint64_t frames_rc;
    uint64_t frames_gps;
    uint64_t frames_battery;
    uint64_t frames_link_stats;
    uint64_t frames_other;
    struct timespec last_frame;
} telemetry_entry_t;

typedef struct {
    bool enabled;
    struct timespec last_write;
    telemetry_entry_t entries[CRSF_SRC_MAX];
    uint64_t last_pkts_uart_to_net;
    uint64_t last_pkts_net_to_uart;
    struct timespec last_rate;
    double tx_pps_hist[5];
    double rx_pps_hist[5];
    size_t pps_hist_count;
    size_t pps_hist_pos;
} telemetry_log_state_t;

#define MSP_STATUS           101
#define MSP_RAW_GPS          106
#define MSP_COMP_GPS         107
#define MSP_ATTITUDE         108
#define MSP_ALTITUDE         109
#define MSP_ANALOG           110
#define MSP_BATTERY_STATE    130
#define MSP_STATUS_EX        150
#define MSP_DISPLAYPORT      182

typedef void (*msp_frame_handler_t)(crsf_source_t src, uint8_t cmd,
                                    const uint8_t *payload, size_t payload_len,
                                    void *user);

typedef struct { uint8_t frame[300]; size_t len; size_t expected; } msp_stream_t;

typedef struct { uint8_t frame[300]; size_t len; size_t expected; bool v2; } mav_stream_t;

typedef enum {
    TELEMETRY_PROTO_UNKNOWN = 0,
    TELEMETRY_PROTO_CRSF,
    TELEMETRY_PROTO_MSP,
    TELEMETRY_PROTO_MAV
} telemetry_proto_t;

typedef struct {
    bool enabled;
    config_proto_t config_proto;
    crsf_monitor_t crsf;
    crsf_frame_handler_t crsf_cb;
    void *crsf_cb_user;

    msp_frame_handler_t msp_cb;
    void *msp_cb_user;

    telemetry_proto_t protocol[CRSF_SRC_MAX];

    msp_stream_t msp_streams[CRSF_SRC_MAX];
    uint64_t msp_frames[CRSF_SRC_MAX];
    uint64_t msp_invalid[CRSF_SRC_MAX];
    uint64_t msp_type_counts[CRSF_SRC_MAX][256];

    mav_stream_t mav_streams[CRSF_SRC_MAX];
    uint64_t mav_frames[CRSF_SRC_MAX];
    uint64_t mav_invalid[CRSF_SRC_MAX];

    struct timespec last_report;
} telemetry_monitor_t;

/* --------------------------------- State ------------------------------------ */
typedef struct {
    // fds
    int fd_uart;     // UART or STDIN
    int fd_stdout;   // only used when uart_backend=STDIO, else -1
    int fd_net;      // UDP socket
    int epfd;

    bool stdout_registered;

    // UDP peer (static outbound)
    struct sockaddr_in udp_peer;
    bool udp_peer_set;

    bool udp_wait_writable;

    // UDP coalesce buffer
    uint8_t *udp_out;
    size_t   udp_out_len;
    size_t   udp_out_cap;

    // CRSF forwarding
    crsf_stream_t crsf_uart_out;
    telemetry_log_state_t log_state;

    // stats
    uint64_t bytes_uart_to_net, bytes_net_to_uart;
    uint64_t pkts_uart_to_net,  pkts_net_to_uart;
    uint64_t drops_uart_to_net, drops_net_to_uart;

    // timers
    struct timespec last_uart_rx; // for UDP idle
    struct timespec last_msp_poll;
    struct timespec last_stats_report;
    uint64_t last_report_pkts_uart_to_net;
    uint64_t last_report_pkts_net_to_uart;
    uint64_t last_report_bytes_uart_to_net;
    uint64_t last_report_bytes_net_to_uart;

    // rings for short-write safety
    ringbuf_t uart_out;  // NET -> UART/STDOUT pending bytes

    bool running;
} state_t;

/* Forward declarations */
static void uart_forward_with_coalesce(const config_t *cfg, state_t *st,
                                       const uint8_t *data, size_t n);

/* ------------------------------- Signals ------------------------------------ */
static volatile sig_atomic_t g_reload = 0, g_stop = 0;
static void on_sighup(int sig){ (void)sig; g_reload = 1; }
static void on_sigterm(int sig){ (void)sig; g_stop = 1; }

/* ------------------------------- Utilities ---------------------------------- */
static int set_nonblock(int fd){ int fl=fcntl(fd,F_GETFL,0); if(fl<0) return -1; return fcntl(fd,F_SETFL,fl|O_NONBLOCK); }
static void trim(char *s){
    if(!s) return;
    size_t n=strlen(s),i=0,j=n;
    while(i<n && isspace((unsigned char)s[i])) i++;
    while(j>i && isspace((unsigned char)s[j-1])) j--;
    if(i>0) memmove(s,s+i,j-i);
    s[j-i]=0;
}
static speed_t baud_to_speed(int baud){
    switch(baud){
        case 9600: return B9600; case 19200: return B19200; case 38400: return B38400;
        case 57600: return B57600; case 115200: return B115200;
#ifdef B230400
        case 230400: return B230400;
#endif
#ifdef B460800
        case 460800: return B460800;
#endif
#ifdef B921600
        case 921600: return B921600;
#endif
        default: return 0;
    }
}

static int set_custom_baud(int fd, int baud){
#if defined(__linux__) && defined(TCGETS2) && defined(TCSETS2)
    struct termios2 tio2;
    if (ioctl(fd, TCGETS2, &tio2) < 0) return -1;
    tio2.c_cflag &= ~CBAUD;
    tio2.c_cflag |= BOTHER;
    tio2.c_ispeed = baud;
    tio2.c_ospeed = baud;
    return ioctl(fd, TCSETS2, &tio2);
#else
    (void)fd; (void)baud;
    errno = EINVAL;
    return -1;
#endif
}
static void get_mono(struct timespec *ts){ clock_gettime(CLOCK_MONOTONIC, ts); }
static long long diff_ms(const struct timespec *a, const struct timespec *b){ return (a->tv_sec-b->tv_sec)*1000LL + (a->tv_nsec-b->tv_nsec)/1000000LL; }

static uint8_t crc8_d5(const uint8_t *d, size_t n)
{
    uint8_t c = 0;
    while (n--) {
        c ^= *d++;
        for (int i = 0; i < 8; i++) {
            if (c & 0x80U) {
                c = (uint8_t)((c << 1) ^ 0xD5U);
            } else {
                c <<= 1;
            }
        }
    }
    return c;
}

static int parse_config(const char *path, config_t *cfg){
    memset(cfg,0,sizeof(*cfg));
    // Defaults
    cfg->uart_backend = UART_TTY;
    cfg->telemetry_proto = PROTO_OFF;
    cfg->telemetry_log_enable = 0;
    strcpy(cfg->telemetry_log_path, "/tmp/crsf_log.msg");
    cfg->telemetry_log_interval = 100;
    cfg->telemetry_coalesce = 0;
    cfg->telemetry_msp_rate = 5;

    strcpy(cfg->uart_device, "/dev/ttyS1");
    cfg->uart_baud=115200; cfg->uart_databits=8; strcpy(cfg->uart_parity,"none"); cfg->uart_stopbits=1; strcpy(cfg->uart_flow,"none");

    strcpy(cfg->udp_bind_addr,"0.0.0.0"); cfg->udp_bind_port=14550; cfg->udp_peer_addr[0]=0; cfg->udp_peer_port=14550;
    cfg->udp_coalesce_bytes=1200; cfg->udp_coalesce_idle_ms=5; cfg->udp_max_datagram=1200;

    cfg->rx_buf=65536; cfg->tx_buf=65536;

    FILE *f=fopen(path,"r"); if(!f) return -1;
    char line[MAX_LINE];
    while(fgets(line,sizeof(line),f)){
        if(line[0]=='#'||line[0]==';') continue;
        char *eq=strchr(line,'='); if(!eq) continue; *eq=0;
        char key[MAX_KEY], val[MAX_VAL];
        strncpy(key,line,sizeof(key)-1); key[sizeof(key)-1]=0;
        strncpy(val,eq+1,sizeof(val)-1); val[sizeof(val)-1]=0;

        char *p = val;
        while(*p){ if(*p=='#' || *p==';'){ *p=0; break; } p++; }

        trim(key); trim(val); if(!*key) continue;

        vlog(1, "Parsed: %s = %s", key, val);

        if(!strcmp(key,"uart_backend")){
            if(!strcmp(val,"tty")) cfg->uart_backend=UART_TTY;
            else if(!strcmp(val,"stdio")) cfg->uart_backend=UART_STDIO;
        } else if(!strcmp(key,"net_mode")){
            if(strcmp(val,"udp_peer")){
                fclose(f);
                errno = EINVAL;
                fprintf(stderr, "Unsupported net_mode '%s' (only udp_peer is allowed)\n", val);
                return -1;
            }
        }
        else if(!strcmp(key,"uart_device")){ strncpy(cfg->uart_device,val,sizeof(cfg->uart_device)-1); cfg->uart_device[sizeof(cfg->uart_device)-1]=0; }
        else if(!strcmp(key,"uart_baud")) cfg->uart_baud=atoi(val);
        else if(!strcmp(key,"uart_databits")) cfg->uart_databits=atoi(val);
        else if(!strcmp(key,"uart_parity")){ strncpy(cfg->uart_parity,val,sizeof(cfg->uart_parity)-1); cfg->uart_parity[sizeof(cfg->uart_parity)-1]=0; }
        else if(!strcmp(key,"uart_stopbits")) cfg->uart_stopbits=atoi(val);
        else if(!strcmp(key,"uart_flow")){ strncpy(cfg->uart_flow,val,sizeof(cfg->uart_flow)-1); cfg->uart_flow[sizeof(cfg->uart_flow)-1]=0; }

        else if(!strcmp(key,"udp_bind_addr")){ strncpy(cfg->udp_bind_addr,val,sizeof(cfg->udp_bind_addr)-1); cfg->udp_bind_addr[sizeof(cfg->udp_bind_addr)-1]=0; }
        else if(!strcmp(key,"udp_bind_port")) cfg->udp_bind_port=atoi(val);
        else if(!strcmp(key,"udp_peer_addr")){ strncpy(cfg->udp_peer_addr,val,sizeof(cfg->udp_peer_addr)-1); cfg->udp_peer_addr[sizeof(cfg->udp_peer_addr)-1]=0; }
        else if(!strcmp(key,"udp_peer_port")) cfg->udp_peer_port=atoi(val);
        else if(!strcmp(key,"udp_coalesce_bytes")) cfg->udp_coalesce_bytes=atoi(val);
        else if(!strcmp(key,"udp_coalesce_idle_ms")) cfg->udp_coalesce_idle_ms=atoi(val);
        else if(!strcmp(key,"udp_max_datagram")) cfg->udp_max_datagram=atoi(val);

        else if(!strcmp(key,"rx_buf")) cfg->rx_buf=(size_t)strtoul(val,NULL,10);
        else if(!strcmp(key,"tx_buf")) cfg->tx_buf=(size_t)strtoul(val,NULL,10);
        else if(!strcmp(key,"telemetry_proto")){
            if (!strcmp(val,"crsf")) cfg->telemetry_proto=PROTO_CRSF;
            else if (!strcmp(val,"msp")) cfg->telemetry_proto=PROTO_MSP;
            else if (!strcmp(val,"mavlink")) cfg->telemetry_proto=PROTO_MAV;
            else cfg->telemetry_proto=PROTO_OFF;
        }
        else if(!strcmp(key,"telemetry_log")) cfg->telemetry_log_enable=atoi(val);
        else if(!strcmp(key,"telemetry_log_path")){
            strncpy(cfg->telemetry_log_path, val, sizeof(cfg->telemetry_log_path) - 1);
            cfg->telemetry_log_path[sizeof(cfg->telemetry_log_path) - 1] = 0;
        }
        else if(!strcmp(key,"telemetry_log_interval")) cfg->telemetry_log_interval=atoi(val);
        else if(!strcmp(key,"telemetry_coalesce")) cfg->telemetry_coalesce=atoi(val);
        else if(!strcmp(key,"telemetry_msp_rate")) cfg->telemetry_msp_rate=atoi(val);
    }
    fclose(f);

    if (cfg->udp_max_datagram <= 0) cfg->udp_max_datagram = 1200;
    if (cfg->udp_coalesce_bytes <= 0 || cfg->udp_coalesce_bytes > cfg->udp_max_datagram)
        cfg->udp_coalesce_bytes = cfg->udp_max_datagram;
    if (cfg->udp_coalesce_idle_ms < 0) cfg->udp_coalesce_idle_ms = 0;
    if (cfg->rx_buf == 0) cfg->rx_buf = 1024;
    if (cfg->tx_buf == 0) cfg->tx_buf = 65536;
    if (cfg->telemetry_log_interval <= 0) cfg->telemetry_log_interval = 100;
    if (cfg->telemetry_msp_rate <= 0) cfg->telemetry_msp_rate = 1;
    if (!cfg->telemetry_log_path[0]) strcpy(cfg->telemetry_log_path, "/tmp/crsf_log.msg");
    cfg->telemetry_coalesce = cfg->telemetry_coalesce ? 1 : 0;

    return 0;
}

/* --------------------------------- UART ------------------------------------- */
static int open_uart(const config_t *cfg){
    int fd = open(cfg->uart_device, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) return -1;

    struct termios tio;
    if (tcgetattr(fd, &tio) < 0) { close(fd); return -1; }
    cfmakeraw(&tio);

    speed_t sp = baud_to_speed(cfg->uart_baud);
    if (sp){
        cfsetispeed(&tio, sp);
        cfsetospeed(&tio, sp);
    } else {
        cfsetispeed(&tio, B38400);
        cfsetospeed(&tio, B38400);
    }

    tio.c_cflag &= ~CSIZE;
    switch (cfg->uart_databits) { case 5: tio.c_cflag|=CS5; break; case 6: tio.c_cflag|=CS6; break;
        case 7: tio.c_cflag|=CS7; break; default: case 8: tio.c_cflag|=CS8; break; }
    if (!strcmp(cfg->uart_parity,"even")) { tio.c_cflag|=PARENB; tio.c_cflag&=~PARODD; }
    else if (!strcmp(cfg->uart_parity,"odd")) { tio.c_cflag|=PARENB; tio.c_cflag|=PARODD; }
    else { tio.c_cflag&=~PARENB; }
    if (cfg->uart_stopbits==2) tio.c_cflag|=CSTOPB; else tio.c_cflag&=~CSTOPB;
    if (!strcmp(cfg->uart_flow,"rtscts")) tio.c_cflag|=CRTSCTS; else tio.c_cflag&=~CRTSCTS;

    tio.c_cflag |= CLOCAL | CREAD;
    tio.c_cc[VMIN]=1; tio.c_cc[VTIME]=0;

    if (tcsetattr(fd, TCSANOW, &tio) < 0) { close(fd); return -1; }

    if (!sp){
        if (set_custom_baud(fd, cfg->uart_baud) < 0){
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
    }
    return fd;
}

/* ------------------------------- Sockets ------------------------------------ */
static int make_udp_bind(const char *addr, int port){
    int fd=socket(AF_INET,SOCK_DGRAM,0); if(fd<0) return -1;
    int one=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(fd,SOL_SOCKET,SO_REUSEPORT,&one,sizeof(one));
#endif
    struct sockaddr_in sa={0}; sa.sin_family=AF_INET; sa.sin_port=htons(port);
    if(inet_pton(AF_INET,addr,&sa.sin_addr)!=1){ close(fd); errno=EINVAL; return -1; }
    if(bind(fd,(struct sockaddr*)&sa,sizeof(sa))<0){ close(fd); return -1; }
    set_nonblock(fd); return fd;
}
static int add_ep(int epfd,int fd,uint32_t ev){ struct epoll_event e={.events=ev,.data.fd=fd}; return epoll_ctl(epfd,EPOLL_CTL_ADD,fd,&e); }
static int mod_ep(int epfd,int fd,uint32_t ev){ struct epoll_event e={.events=ev,.data.fd=fd}; return epoll_ctl(epfd,EPOLL_CTL_MOD,fd,&e); }
static int del_ep(int epfd,int fd){ return epoll_ctl(epfd,EPOLL_CTL_DEL,fd,NULL); }
static void close_fd(int *fd){ if(*fd>=0){ close(*fd); *fd=-1; } }

/* --------------------------- Short-write helpers ---------------------------- */
static ssize_t write_from_ring_fd(int fd, ringbuf_t *r){
    const uint8_t *p1,*p2; size_t l1,l2; ssize_t total=0;
    ring_peek(r,&p1,&l1,&p2,&l2);
    if(l1){ ssize_t w=write(fd,p1,l1); if(w>0){ ring_consume(r,(size_t)w); total+=w; } else return w; }
    if(r->len && l2){ ring_peek(r,&p1,&l1,&p2,&l2); if(l2){ ssize_t w=write(fd,p2,l2); if(w>0){ ring_consume(r,(size_t)w); total+=w; } else return (total>0?total:w); } }
    return total;
}

/* ------------------------ Open/close based on config ------------------------ */
static int reopen_everything(const config_t *cfg, state_t *st){
    vlog(2, "Reopen: closing existing fds");
    if (st->fd_net    >=0){ del_ep(st->epfd,st->fd_net);    close_fd(&st->fd_net); }
    if (cfg->uart_backend==UART_TTY && st->fd_uart>=0){ del_ep(st->epfd,st->fd_uart); close_fd(&st->fd_uart); }
    if (st->fd_stdout>=0 && st->stdout_registered){ del_ep(st->epfd,st->fd_stdout); st->stdout_registered=false; }
    st->fd_stdout=-1;

    st->udp_peer_set=false;
    st->udp_out_len=0;
    st->udp_wait_writable=false;

    ring_free(&st->uart_out);
    if(ring_init(&st->uart_out,cfg->tx_buf)<0){
        vlog(1, "ring buffer allocation failed (%s)", strerror(errno));
        return -1;
    }

    // UART / STDIO
    if (cfg->uart_backend==UART_STDIO){
        st->fd_uart=STDIN_FILENO; st->fd_stdout=STDOUT_FILENO;
        set_nonblock(st->fd_uart); set_nonblock(st->fd_stdout);
        setvbuf(stdout,NULL,_IONBF,0);
        add_ep(st->epfd, st->fd_uart, EPOLLIN);
        vlog(1, "UART backend: stdio (stdin/stdout)");
    } else {
        st->fd_uart = open_uart(cfg);
        if(st->fd_uart<0) { vlog(1,"UART open failed (%s)", strerror(errno)); return -1; }
        set_nonblock(st->fd_uart); add_ep(st->epfd, st->fd_uart, EPOLLIN);
        vlog(1, "UART backend: tty dev=%s baud=%d %d%s%d flow=%s",
             cfg->uart_device, cfg->uart_baud, cfg->uart_databits,
             (!strcmp(cfg->uart_parity,"none")?"N":(!strcmp(cfg->uart_parity,"even")?"E":"O")),
             cfg->uart_stopbits, cfg->uart_flow);
    }

    // UDP
    st->fd_net=make_udp_bind(cfg->udp_bind_addr,cfg->udp_bind_port); if(st->fd_net<0){ vlog(1,"UDP bind failed (%s)", strerror(errno)); return -1; }
    add_ep(st->epfd, st->fd_net, EPOLLIN);
    if(cfg->udp_peer_addr[0]){
        memset(&st->udp_peer,0,sizeof(st->udp_peer));
        st->udp_peer.sin_family=AF_INET; st->udp_peer.sin_port=htons(cfg->udp_peer_port);
        if(inet_pton(AF_INET,cfg->udp_peer_addr,&st->udp_peer.sin_addr)==1) st->udp_peer_set=true;
    }

    vlog(1, "UDP peer: bind %s:%d -> peer %s:%d (coalesce=%dB/%dms, max=%dB)",
         cfg->udp_bind_addr, cfg->udp_bind_port,
         cfg->udp_peer_addr[0]?cfg->udp_peer_addr:"(unset)", cfg->udp_peer_port,
         cfg->udp_coalesce_bytes, cfg->udp_coalesce_idle_ms, cfg->udp_max_datagram);
    return 0;
}

/* ----------------------------- UDP coalescing ------------------------------- */
static void udp_flush_if_ready(const config_t *cfg, state_t *st, bool force, const char *reason){
    if(!st->udp_peer_set){ st->udp_out_len=0; st->udp_wait_writable=false; return; }
    if(st->udp_out_len==0) return;

    bool size_ready = (int)st->udp_out_len >= cfg->udp_coalesce_bytes;
    bool send_now = force || size_ready || cfg->udp_coalesce_idle_ms==0;
    if(!send_now) return;

    ssize_t w = sendto(st->fd_net, st->udp_out, st->udp_out_len, 0,
                       (struct sockaddr*)&st->udp_peer, sizeof(st->udp_peer));
    if(w==(ssize_t)st->udp_out_len){
        st->bytes_uart_to_net += (uint64_t)w; st->pkts_uart_to_net += 1;
        vlog(3, "UDP: sent datagram bytes=%zd reason=%s", w, reason?reason:"(unknown)");
        st->udp_out_len=0;
        st->udp_wait_writable=false;
    } else if(w<0 && (errno==EAGAIN||errno==EWOULDBLOCK||errno==ENOBUFS)){
        st->udp_wait_writable=true;
        vlog(2, "UDP: EAGAIN/ENOBUFS (reason=%s), will retry", reason?reason:"(unknown)");
    } else {
        st->drops_uart_to_net += st->udp_out_len;
        vlog(1, "UDP: send error (%d) dropping datagram reason=%s", errno, reason?reason:"(unknown)");
        st->udp_out_len=0;
        st->udp_wait_writable=false;
    }
}

/* --------------------------- Stats helpers ---------------------------------- */
static void reset_stats_window(state_t *st){
    memset(&st->last_stats_report, 0, sizeof(st->last_stats_report));
    st->last_report_pkts_uart_to_net = st->pkts_uart_to_net;
    st->last_report_pkts_net_to_uart = st->pkts_net_to_uart;
    st->last_report_bytes_uart_to_net = st->bytes_uart_to_net;
    st->last_report_bytes_net_to_uart = st->bytes_net_to_uart;
}

static void maybe_print_stats(state_t *st){
    if(!g_verbosity) return;
    struct timespec now;
    get_mono(&now);
    if(st->last_stats_report.tv_sec==0 && st->last_stats_report.tv_nsec==0){
        st->last_stats_report = now;
        st->last_report_pkts_uart_to_net = st->pkts_uart_to_net;
        st->last_report_pkts_net_to_uart = st->pkts_net_to_uart;
        st->last_report_bytes_uart_to_net = st->bytes_uart_to_net;
        st->last_report_bytes_net_to_uart = st->bytes_net_to_uart;
        return;
    }

    long long elapsed_ms = diff_ms(&now, &st->last_stats_report);
    if(elapsed_ms < 1000) return;

    double secs = (double)elapsed_ms / 1000.0;
    uint64_t tx_pkts_delta = st->pkts_uart_to_net - st->last_report_pkts_uart_to_net;
    uint64_t rx_pkts_delta = st->pkts_net_to_uart - st->last_report_pkts_net_to_uart;
    uint64_t tx_bytes_delta = st->bytes_uart_to_net - st->last_report_bytes_uart_to_net;
    uint64_t rx_bytes_delta = st->bytes_net_to_uart - st->last_report_bytes_net_to_uart;

    double tx_pps = secs>0.0 ? (double)tx_pkts_delta / secs : 0.0;
    double rx_pps = secs>0.0 ? (double)rx_pkts_delta / secs : 0.0;
    double tx_bps = secs>0.0 ? (double)tx_bytes_delta / secs : 0.0;
    double rx_bps = secs>0.0 ? (double)rx_bytes_delta / secs : 0.0;

    fprintf(stderr,
            "[stats] tx %.1f pkts/s (%.0f B/s) rx %.1f pkts/s (%.0f B/s) drops tx=%llu rx=%llu totals tx=%llu rx=%llu\n",
            tx_pps, tx_bps, rx_pps, rx_bps,
            (unsigned long long)st->drops_uart_to_net,
            (unsigned long long)st->drops_net_to_uart,
            (unsigned long long)st->pkts_uart_to_net,
            (unsigned long long)st->pkts_net_to_uart);

    st->last_stats_report = now;
    st->last_report_pkts_uart_to_net = st->pkts_uart_to_net;
    st->last_report_pkts_net_to_uart = st->pkts_net_to_uart;
    st->last_report_bytes_uart_to_net = st->bytes_uart_to_net;
    st->last_report_bytes_net_to_uart = st->bytes_net_to_uart;
}

/* ------------------------------ CRSF support -------------------------------- */
/* CRSF monitor */
static void crsf_monitor_init(crsf_monitor_t *m, bool enabled,
                              crsf_frame_handler_t on_frame, void *user)
{
    memset(m, 0, sizeof(*m));
    m->enabled = enabled;
    m->on_frame = on_frame;
    m->on_frame_user = user;

    static const uint8_t known_types[] = {
        0x02, /* GPS */
        0x07, /* Vario */
        0x08, /* Battery sensor */
        0x09, /* Baro altitude */
        0x0B, /* Heartbeat */
        0x0F, /* Video transmitter */
        0x10, /* OpenTX sync */
        0x14, /* Link statistics */
        0x16, /* RC channels packed */
        0x1C, /* Link RX ID */
        0x1D, /* Link TX ID */
        0x1E, /* Attitude */
        0x21, /* Flight mode */
        0x28, /* Device ping */
        0x29, /* Device info */
        0x2B, /* Parameter settings entry */
        0x2C, /* Parameter read */
        0x2D, /* Parameter write */
        0x32, /* Command */
        0x3A, /* Radio ID */
        0x78, /* KISS request */
        0x79, /* KISS response */
        0x7A, /* MSP request */
        0x7B, /* MSP response */
        0x7C, /* MSP write */
        0x80, /* Ardupilot response */
    };

    for (size_t i = 0; i < sizeof(known_types); i++) {
        m->recognized_types[known_types[i]] = true;
    }
}

static void crsf_monitor_set_enabled(crsf_monitor_t *m, bool enabled)
{
    if (m->enabled == enabled) return;
    crsf_frame_handler_t cb = m->on_frame;
    void *user = m->on_frame_user;
    crsf_monitor_init(m, enabled, cb, user);
}

static void crsf_stream_reset(crsf_stream_t *s)
{
    s->len = 0;
    s->expected = 0;
}

static void crsf_monitor_handle_frame(crsf_monitor_t *m, crsf_source_t src, crsf_stream_t *s)
{
    if (!m->enabled) return;

    uint8_t len_field = s->frame[1];
    size_t total = (size_t)len_field + 2;
    if (len_field < 2 || total != s->len || total < 4 || total > sizeof(s->frame)) {
        m->invalid_frames[src]++;
        return;
    }

    size_t payload_len = (size_t)len_field >= 2 ? (size_t)len_field - 2 : 0;
    size_t crc_off = total - 1;
    uint8_t expected_crc = s->frame[crc_off];
    uint8_t calc_crc = crc8_d5(s->frame + 2, (size_t)len_field - 1);
    if (calc_crc != expected_crc) {
        m->invalid_frames[src]++;
        return;
    }

    uint8_t type = s->frame[2];
    m->type_counts[src][type] += 1;
    if (m->on_frame) {
        const uint8_t *payload = s->frame + 3;
        m->on_frame(src, type, payload, payload_len, m->on_frame_user);
    }

    if (!m->recognized_types[type] && !m->unknown_reported[type]) {
        vlog(1, "CRSF: unrecognized frame type 0x%02X (len=%zu)", type, s->len);
        m->unknown_reported[type] = true;
    }
}

static void crsf_monitor_feed(crsf_monitor_t *m, crsf_source_t src, const uint8_t *data, size_t n)
{
    if (!m->enabled) return;

    crsf_stream_t *s = &m->streams[src];

    for (size_t i = 0; i < n; i++) {
        uint8_t b = data[i];

        if (s->len == 0) {
            s->frame[0] = b;
            s->len = 1;
            s->expected = 0;
            continue;
        }

        if (s->len == 1) {
            s->frame[1] = b;
            s->len = 2;
            size_t total = (size_t)b + 2;
            if (total < 4 || total > sizeof(s->frame)) {
                crsf_stream_reset(s);
            } else {
                s->expected = total;
            }
            continue;
        }

        if (s->len < sizeof(s->frame)) {
            s->frame[s->len] = b;
        }
        s->len++;

        if (s->expected && s->len == s->expected) {
            crsf_monitor_handle_frame(m, src, s);
            crsf_stream_reset(s);
        } else if (s->len >= sizeof(s->frame)) {
            crsf_stream_reset(s);
        }
    }
}

static void crsf_monitor_maybe_report(crsf_monitor_t *m)
{
    // If not enabled or verbosity off, skip.
    // Also, if the parent telemetry monitor has force-set a protocol other than CRSF, we shouldn't be here ideally,
    // but m->enabled handles that (we init m->crsf with enabled only if PROTO_CRSF).
    if (!m->enabled || !g_verbosity) return;

    struct timespec now;
    get_mono(&now);
    if (m->last_report.tv_sec == 0 && m->last_report.tv_nsec == 0) {
        m->last_report = now;
        return;
    }

    long long elapsed_ms = diff_ms(&now, &m->last_report);
    if (elapsed_ms < 1000) return;

    uint64_t totals_valid[CRSF_SRC_MAX] = {0};
    uint64_t rc_channels[CRSF_SRC_MAX] = {0};
    uint64_t gps[CRSF_SRC_MAX] = {0};
    uint64_t battery[CRSF_SRC_MAX] = {0};
    uint64_t link_stats[CRSF_SRC_MAX] = {0};
    uint64_t attitude[CRSF_SRC_MAX] = {0};
    uint64_t flight_mode[CRSF_SRC_MAX] = {0};
    uint64_t other[CRSF_SRC_MAX] = {0};
    uint64_t unknown[CRSF_SRC_MAX] = {0};
    uint64_t total_all[CRSF_SRC_MAX] = {0};

    for (int s = 0; s < CRSF_SRC_MAX; s++) {
        for (int i = 0; i < 256; i++) {
            totals_valid[s] += m->type_counts[s][i];
        }

        rc_channels[s] = m->type_counts[s][0x16];
        gps[s]        = m->type_counts[s][0x02];
        battery[s]    = m->type_counts[s][0x08];
        link_stats[s] = m->type_counts[s][0x14];
        attitude[s]   = m->type_counts[s][0x1E];
        flight_mode[s]= m->type_counts[s][0x21];

        uint64_t recognized_sum = 0;
        for (int t = 0; t < 256; t++) {
            if (m->recognized_types[t]) {
                recognized_sum += m->type_counts[s][t];
            }
        }

        uint64_t named_sum = rc_channels[s] + gps[s] + battery[s] + link_stats[s] + attitude[s] + flight_mode[s];
        if (recognized_sum >= named_sum) {
            other[s] = recognized_sum - named_sum;
        }
        if (totals_valid[s] >= recognized_sum) {
            unknown[s] = totals_valid[s] - recognized_sum;
        }
        total_all[s] = totals_valid[s] + m->invalid_frames[s];
    }

    fprintf(stderr,
            "[crsf] uart rc=%llu gps=%llu bat=%llu lnk=%llu att=%llu mode=%llu oth=%llu unk=%llu inv=%llu tot=%llu\n"
            "       udp  rc=%llu gps=%llu bat=%llu lnk=%llu att=%llu mode=%llu oth=%llu unk=%llu inv=%llu tot=%llu\n",
            (unsigned long long)rc_channels[CRSF_FROM_UART],
            (unsigned long long)gps[CRSF_FROM_UART],
            (unsigned long long)battery[CRSF_FROM_UART],
            (unsigned long long)link_stats[CRSF_FROM_UART],
            (unsigned long long)attitude[CRSF_FROM_UART],
            (unsigned long long)flight_mode[CRSF_FROM_UART],
            (unsigned long long)other[CRSF_FROM_UART],
            (unsigned long long)unknown[CRSF_FROM_UART],
            (unsigned long long)m->invalid_frames[CRSF_FROM_UART],
            (unsigned long long)total_all[CRSF_FROM_UART],
            (unsigned long long)rc_channels[CRSF_FROM_UDP],
            (unsigned long long)gps[CRSF_FROM_UDP],
            (unsigned long long)battery[CRSF_FROM_UDP],
            (unsigned long long)link_stats[CRSF_FROM_UDP],
            (unsigned long long)attitude[CRSF_FROM_UDP],
            (unsigned long long)flight_mode[CRSF_FROM_UDP],
            (unsigned long long)other[CRSF_FROM_UDP],
            (unsigned long long)unknown[CRSF_FROM_UDP],
            (unsigned long long)m->invalid_frames[CRSF_FROM_UDP],
            (unsigned long long)total_all[CRSF_FROM_UDP]);
    fflush(stderr);

    m->last_report = now;

    for (int s = 0; s < CRSF_SRC_MAX; s++) {
        memset(m->type_counts[s], 0, sizeof(m->type_counts[s]));
        m->invalid_frames[s] = 0;
    }
}

static void msp_send_query(ringbuf_t *r, uint8_t cmd)
{
    // MSP v1 request: $ M < 0 cmd checksum
    uint8_t buf[6];
    buf[0] = '$';
    buf[1] = 'M';
    buf[2] = '<';
    buf[3] = 0;
    buf[4] = cmd;
    buf[5] = 0 ^ cmd; // checksum for size=0 is cmd^size = cmd^0 = cmd

    ring_write(r, buf, 6);
}

static void msp_monitor_print_report(telemetry_monitor_t *m, long long elapsed_ms)
{
    (void)elapsed_ms;
    // status(101/150), gps(106/107), bat(110/130), att(108), alt(109), disp(182), oth, unk
    uint64_t status[CRSF_SRC_MAX] = {0};
    uint64_t gps[CRSF_SRC_MAX] = {0};
    uint64_t battery[CRSF_SRC_MAX] = {0};
    uint64_t att[CRSF_SRC_MAX] = {0};
    uint64_t alt[CRSF_SRC_MAX] = {0};
    uint64_t disp[CRSF_SRC_MAX] = {0};
    uint64_t other[CRSF_SRC_MAX] = {0};
    uint64_t total[CRSF_SRC_MAX] = {0};

    for (int s = 0; s < CRSF_SRC_MAX; s++) {
        for (int i = 0; i < 256; i++) {
            uint64_t c = m->msp_type_counts[s][i];
            total[s] += c;
            if (i == MSP_STATUS || i == MSP_STATUS_EX) status[s] += c;
            else if (i == MSP_RAW_GPS || i == MSP_COMP_GPS) gps[s] += c;
            else if (i == MSP_ANALOG || i == MSP_BATTERY_STATE) battery[s] += c;
            else if (i == MSP_ATTITUDE) att[s] += c;
            else if (i == MSP_ALTITUDE) alt[s] += c;
            else if (i == MSP_DISPLAYPORT) disp[s] += c;
            else other[s] += c;
        }
    }

    // Only print if there is some MSP activity
    if (total[CRSF_FROM_UART] > 0 || total[CRSF_FROM_UDP] > 0) {
        char oth_detail[64] = {0};
        if (other[CRSF_FROM_UART] > 0) {
            // Find top unhandled ID
            int max_id = -1; uint64_t max_c = 0;
            for (int i = 0; i < 256; i++) {
                if (i == MSP_STATUS || i == MSP_STATUS_EX || i == MSP_RAW_GPS || i == MSP_COMP_GPS ||
                    i == MSP_ANALOG || i == MSP_BATTERY_STATE || i == MSP_ATTITUDE || i == MSP_ALTITUDE || i == MSP_DISPLAYPORT) continue;
                if (m->msp_type_counts[CRSF_FROM_UART][i] > max_c) {
                    max_c = m->msp_type_counts[CRSF_FROM_UART][i];
                    max_id = i;
                }
            }
            if (max_id >= 0) snprintf(oth_detail, sizeof(oth_detail), " (top_oth:0x%02X=%llu)", max_id, (unsigned long long)max_c);
        }

        fprintf(stderr,
            "[msp]  uart stat=%llu gps=%llu bat=%llu att=%llu alt=%llu disp=%llu oth=%llu%s inv=%llu tot=%llu\n"
            "       udp  stat=%llu gps=%llu bat=%llu att=%llu alt=%llu disp=%llu oth=%llu inv=%llu tot=%llu\n",
            (unsigned long long)status[CRSF_FROM_UART],
            (unsigned long long)gps[CRSF_FROM_UART],
            (unsigned long long)battery[CRSF_FROM_UART],
            (unsigned long long)att[CRSF_FROM_UART],
            (unsigned long long)alt[CRSF_FROM_UART],
            (unsigned long long)disp[CRSF_FROM_UART],
            (unsigned long long)other[CRSF_FROM_UART],
            oth_detail,
            (unsigned long long)m->msp_invalid[CRSF_FROM_UART],
            (unsigned long long)m->msp_frames[CRSF_FROM_UART],
            (unsigned long long)status[CRSF_FROM_UDP],
            (unsigned long long)gps[CRSF_FROM_UDP],
            (unsigned long long)battery[CRSF_FROM_UDP],
            (unsigned long long)att[CRSF_FROM_UDP],
            (unsigned long long)alt[CRSF_FROM_UDP],
            (unsigned long long)disp[CRSF_FROM_UDP],
            (unsigned long long)other[CRSF_FROM_UDP],
            (unsigned long long)m->msp_invalid[CRSF_FROM_UDP],
            (unsigned long long)m->msp_frames[CRSF_FROM_UDP]);
    }

    for (int s = 0; s < CRSF_SRC_MAX; s++) {
        memset(m->msp_type_counts[s], 0, sizeof(m->msp_type_counts[s]));
        // Note: msp_frames and msp_invalid are reset in telemetry_monitor_maybe_report
    }
}

/* Telemetry monitor wrapper */
static void telemetry_monitor_init(telemetry_monitor_t *m, bool enabled, config_proto_t forced_proto,
                                   crsf_frame_handler_t crsf_cb,
                                   void *crsf_cb_user,
                                   msp_frame_handler_t msp_cb,
                                   void *msp_cb_user)
{
    memset(m, 0, sizeof(*m));
    m->enabled = enabled;
    m->config_proto = forced_proto;

    telemetry_proto_t p = TELEMETRY_PROTO_UNKNOWN;
    if (forced_proto == PROTO_CRSF) p = TELEMETRY_PROTO_CRSF;
    else if (forced_proto == PROTO_MSP) p = TELEMETRY_PROTO_MSP;
    else if (forced_proto == PROTO_MAV) p = TELEMETRY_PROTO_MAV;
    for(int i=0; i<CRSF_SRC_MAX; i++) m->protocol[i] = p;

    m->crsf_cb = crsf_cb;
    m->crsf_cb_user = crsf_cb_user;
    m->msp_cb = msp_cb;
    m->msp_cb_user = msp_cb_user;
    crsf_monitor_init(&m->crsf, enabled, crsf_cb, crsf_cb_user);
}

static void telemetry_monitor_set_enabled(telemetry_monitor_t *m, bool enabled, config_proto_t forced_proto)
{
    if (m->enabled == enabled && m->config_proto == forced_proto) return;
    crsf_frame_handler_t crsf_cb = m->crsf_cb;
    void *crsf_user = m->crsf_cb_user;
    msp_frame_handler_t msp_cb = m->msp_cb;
    void *msp_user = m->msp_cb_user;
    telemetry_monitor_init(m, enabled, forced_proto, crsf_cb, crsf_user, msp_cb, msp_user);
}

static void msp_stream_reset(msp_stream_t *s)
{
    s->len = 0;
    s->expected = 0;
}

static void telemetry_monitor_feed_msp(telemetry_monitor_t *m, crsf_source_t src,
                                       const uint8_t *data, size_t n)
{
    msp_stream_t *s = &m->msp_streams[src];

    for (size_t i = 0; i < n; i++) {
        uint8_t b = data[i];

        if (s->len == 0) {
            if (b == '$') {
                s->frame[0] = b;
                s->len = 1;
            }
            continue;
        }

        if (s->len == 1) {
            if (b == 'M') {
                s->frame[1] = b;
                s->len = 2;
            } else {
                msp_stream_reset(s);
                if (b == '$') {
                    s->frame[0] = b;
                    s->len = 1;
                }
            }
            continue;
        }

        if (s->len == 2) {
            if (b == '<' || b == '>') {
                s->frame[2] = b;
                s->len = 3;
            } else {
                msp_stream_reset(s);
                if (b == '$') {
                    s->frame[0] = b;
                    s->len = 1;
                }
            }
            continue;
        }

        if (s->len == 3) {
            s->frame[3] = b;
            s->len = 4;
            size_t payload_len = b;
            size_t total = payload_len + 6;
            if (total < 6 || total > sizeof(s->frame)) {
                m->msp_invalid[src]++;
                msp_stream_reset(s);
            } else {
                s->expected = total;
            }
            continue;
        }

        if (s->len < sizeof(s->frame)) {
            s->frame[s->len] = b;
        }
        s->len++;

        if (s->expected && s->len == s->expected) {
            if (s->expected >= 6) {
                uint8_t checksum = 0;
                for (size_t j = 3; j + 1 < s->expected; j++) {
                    checksum ^= s->frame[j];
                }
                uint8_t expected_checksum = s->frame[s->expected - 1];
                if (checksum == expected_checksum) {
                    m->msp_frames[src]++;
                    if (s->expected >= 6) {
                        uint8_t cmd = s->frame[4];
                        m->msp_type_counts[src][cmd]++;

                        if (m->msp_cb) {
                            // Frame structure: $ M < len cmd payload... checksum
                            // cmd is at index 4, payload starts at 5, len is s->frame[3]
                            size_t payload_len = s->frame[3];
                            if (5 + payload_len < s->expected) {
                                m->msp_cb(src, cmd, s->frame + 5, payload_len, m->msp_cb_user);
                            }
                        }
                    }
                } else {
                    m->msp_invalid[src]++;
                }
            } else {
                m->msp_invalid[src]++;
            }
            msp_stream_reset(s);
        } else if (s->expected && s->len > s->expected) {
            m->msp_invalid[src]++;
            msp_stream_reset(s);
        } else if (s->len >= sizeof(s->frame)) {
            m->msp_invalid[src]++;
            msp_stream_reset(s);
        }
    }
}

static void mav_stream_reset(mav_stream_t *s)
{
    s->len = 0;
    s->expected = 0;
    s->v2 = false;
}

static size_t mav_stream_expected(const mav_stream_t *s)
{
    if ( s->len < 2) return 0;
    size_t payload_len = s->frame[1];
    if (s->v2) {
        if (s->len < 3) return 0;
        uint8_t incompat = s->frame[2];
        size_t signature = (incompat & 0x01U) ? 13U : 0U;
        return 10 + payload_len + 2 + signature;
    }

    return 6 + payload_len + 2;
}

static void telemetry_monitor_feed_mav(telemetry_monitor_t *m, crsf_source_t src,
                                       const uint8_t *data, size_t n)
{
    mav_stream_t *s = &m->mav_streams[src];

    for (size_t i = 0; i < n; i++) {
        uint8_t b = data[i];

        if (s->len == 0) {
            if (b == 0xFE || b == 0xFD) {
                s->frame[0] = b;
                s->len = 1;
                s->v2 = (b == 0xFD);
            }
            continue;
        }

        if (s->len < sizeof(s->frame)) {
            s->frame[s->len] = b;
        }
        s->len++;

        if (s->len == 2 || (s->v2 && s->len == 3)) {
            s->expected = mav_stream_expected(s);
            if (!s->expected || s->expected > sizeof(s->frame)) {
                m->mav_invalid[src]++;
                mav_stream_reset(s);
            }
            continue;
        }

        if (s->expected && s->len == s->expected) {
            m->mav_frames[src]++;
            mav_stream_reset(s);
        } else if (s->expected && s->len > s->expected) {
            m->mav_invalid[src]++;
            mav_stream_reset(s);
        } else if (s->len >= sizeof(s->frame)) {
            m->mav_invalid[src]++;
            mav_stream_reset(s);
        }
    }
}

static void telemetry_monitor_feed(telemetry_monitor_t *m, crsf_source_t src,
                                   const uint8_t *data, size_t n)
{
    if (!m->enabled) return;

    telemetry_proto_t proto = m->protocol[src];

    if (proto == TELEMETRY_PROTO_MSP) {
        telemetry_monitor_feed_msp(m, src, data, n);
    } else if (proto == TELEMETRY_PROTO_MAV) {
        telemetry_monitor_feed_mav(m, src, data, n);
    } else if (proto == TELEMETRY_PROTO_CRSF) {
        crsf_monitor_feed(&m->crsf, src, data, n);
    }
}

static void telemetry_monitor_maybe_report(telemetry_monitor_t *m)
{
    if (!m->enabled || !g_verbosity) return;

    // Report CRSF stats only if configured for CRSF
    if (m->config_proto == PROTO_CRSF) {
        crsf_monitor_maybe_report(&m->crsf);
    }

    struct timespec now;
    get_mono(&now);
    if (m->last_report.tv_sec == 0 && m->last_report.tv_nsec == 0) {
        m->last_report = now;
        return;
    }

    long long elapsed_ms = diff_ms(&now, &m->last_report);
    if (elapsed_ms < 1000) return;

    if (m->config_proto == PROTO_MSP) {
        msp_monitor_print_report(m, elapsed_ms);
        fprintf(stderr,
            "[telemetry] msp uart=%llu udp=%llu inv=%llu\n",
            (unsigned long long)m->msp_frames[CRSF_FROM_UART],
            (unsigned long long)m->msp_frames[CRSF_FROM_UDP],
            (unsigned long long)(m->msp_invalid[CRSF_FROM_UART] +
                                 m->msp_invalid[CRSF_FROM_UDP]));
    } else if (m->config_proto == PROTO_MAV) {
        fprintf(stderr,
            "[telemetry] mav uart=%llu udp=%llu inv=%llu\n",
            (unsigned long long)m->mav_frames[CRSF_FROM_UART],
            (unsigned long long)m->mav_frames[CRSF_FROM_UDP],
            (unsigned long long)(m->mav_invalid[CRSF_FROM_UART] +
                                 m->mav_invalid[CRSF_FROM_UDP]));
    }

    m->last_report = now;
    memset(m->msp_frames, 0, sizeof(m->msp_frames));
    memset(m->msp_invalid, 0, sizeof(m->msp_invalid));
    memset(m->mav_frames, 0, sizeof(m->mav_frames));
    memset(m->mav_invalid, 0, sizeof(m->mav_invalid));
}

/* CRSF logging */
typedef struct {
    const config_t *cfg;
    telemetry_log_state_t *log;
    const state_t *st;
} telemetry_log_ctx_t;

static void telemetry_update_crsf(const config_t *cfg, telemetry_log_state_t *log, const state_t *st,
                            crsf_source_t src, uint8_t type, const uint8_t *payload,
                            size_t payload_len);

static void telemetry_log_on_crsf_frame(crsf_source_t src, uint8_t type, const uint8_t *payload,
                              size_t payload_len, void *user)
{
    telemetry_log_ctx_t *ctx = (telemetry_log_ctx_t *)user;
    if (!ctx || !ctx->cfg || !ctx->log || !ctx->st) return;

    telemetry_update_crsf(ctx->cfg, ctx->log, ctx->st, src, type, payload, payload_len);
}

static void telemetry_update_msp(const config_t *cfg, telemetry_log_state_t *log, const state_t *st,
                           crsf_source_t src, uint8_t cmd, const uint8_t *payload,
                           size_t payload_len);

static void telemetry_log_on_msp_frame(crsf_source_t src, uint8_t cmd, const uint8_t *payload,
                             size_t payload_len, void *user)
{
    telemetry_log_ctx_t *ctx = (telemetry_log_ctx_t *)user;
    if (!ctx || !ctx->cfg || !ctx->log || !ctx->st) return;

    telemetry_update_msp(ctx->cfg, ctx->log, ctx->st, src, cmd, payload, payload_len);
}

static void telemetry_log_reset(telemetry_log_state_t *log)
{
    memset(log, 0, sizeof(*log));
}

static void telemetry_log_init(telemetry_log_state_t *log, const config_t *cfg)
{
    bool new_enabled = (cfg->telemetry_proto != PROTO_OFF) && cfg->telemetry_log_enable && cfg->telemetry_log_path[0];

    if (!new_enabled) {
        telemetry_log_reset(log);
        return;
    }

    if (!log->enabled) {
        log->last_write.tv_sec = 0;
        log->last_write.tv_nsec = 0;
    }

    log->enabled = true;
}

static const char *crsf_log_prefix(crsf_source_t src)
{
    return (src == CRSF_FROM_UART) ? "" : "udp_";
}

static void telemetry_log_write(const config_t *cfg, telemetry_log_state_t *log,
                                 const state_t *st)
{
    if (!log->enabled || !st) return;

    struct timespec now_ts;
    get_mono(&now_ts);
    double now_s = (double)now_ts.tv_sec + (double)now_ts.tv_nsec / 1e9;

    // Maintain flight time state
    for (int i = 0; i < CRSF_SRC_MAX; i++) {
        telemetry_entry_t *entry = &log->entries[i];
        if (entry->armed && !entry->prev_armed) {
            entry->armed_start_time = now_s;
        }
        if (!entry->armed && entry->prev_armed) {
            entry->armed_accumulated_s += (now_s - entry->armed_start_time);
        }
        entry->prev_armed = entry->armed;
    }

    if (log->last_write.tv_sec || log->last_write.tv_nsec) {
        if (diff_ms(&now_ts, &log->last_write) < cfg->telemetry_log_interval) return;
    }

    FILE *f = fopen(cfg->telemetry_log_path, "w");
    if (!f) {
        vlog(2, "CRSF log: failed to open %s (%s)", cfg->telemetry_log_path, strerror(errno));
        return;
    }

    long long elapsed_ms = 0;
    if (log->last_rate.tv_sec || log->last_rate.tv_nsec) {
        elapsed_ms = diff_ms(&now_ts, &log->last_rate);
    }
    if (elapsed_ms <= 0) {
        log->last_pkts_uart_to_net = st->pkts_uart_to_net;
        log->last_pkts_net_to_uart = st->pkts_net_to_uart;
        log->last_rate = now_ts;
        elapsed_ms = cfg->telemetry_log_interval;
    }

    uint64_t delta_tx = st->pkts_uart_to_net - log->last_pkts_uart_to_net;
    uint64_t delta_rx = st->pkts_net_to_uart - log->last_pkts_net_to_uart;
    double tx_pps = (double)delta_tx * 1000.0 / (double)elapsed_ms;
    double rx_pps = (double)delta_rx * 1000.0 / (double)elapsed_ms;
    log->tx_pps_hist[log->pps_hist_pos] = tx_pps;
    log->rx_pps_hist[log->pps_hist_pos] = rx_pps;
    if (log->pps_hist_count < 5) log->pps_hist_count++;
    log->pps_hist_pos = (log->pps_hist_pos + 1) % 5;

    double tx_pps_sum = 0.0, rx_pps_sum = 0.0;
    for (size_t i = 0; i < log->pps_hist_count; i++) {
        tx_pps_sum += log->tx_pps_hist[i];
        rx_pps_sum += log->rx_pps_hist[i];
    }
    size_t recent_idx = (log->pps_hist_pos + 4) % 5;
    double tx_recent = log->tx_pps_hist[recent_idx];
    double rx_recent = log->rx_pps_hist[recent_idx];
    double recent_weight = 2.0; /* bias toward the newest sample for responsiveness */
    double tx_pps_avg = tx_pps_sum;
    double rx_pps_avg = rx_pps_sum;
    if (log->pps_hist_count > 0) {
        tx_pps_avg = (tx_pps_sum - tx_recent + tx_recent * recent_weight) /
                     (recent_weight + (double)(log->pps_hist_count - 1));
        rx_pps_avg = (rx_pps_sum - rx_recent + rx_recent * recent_weight) /
                     (recent_weight + (double)(log->pps_hist_count - 1));
    }
    double tx_kpkts = (double)st->pkts_uart_to_net / 1000.0;
    double rx_kpkts = (double)st->pkts_net_to_uart / 1000.0;

    fprintf(f, "tx_pps=%.1f\n", tx_pps_avg);
    fprintf(f, "rx_pps=%.1f\n", rx_pps_avg);
    fprintf(f, "tx_kpkts=%.1f\n", tx_kpkts);
    fprintf(f, "rx_kpkts=%.1f\n", rx_kpkts);

    log->last_pkts_uart_to_net = st->pkts_uart_to_net;
    log->last_pkts_net_to_uart = st->pkts_net_to_uart;
    log->last_rate = now_ts;

    {
        const telemetry_entry_t *entry = &log->entries[CRSF_FROM_UART];
        const char *prefix = "";

        if (entry->has_battery) {
            fprintf(f, "%svoltage=%.1f\n", prefix, entry->voltage_v);
            fprintf(f, "%scurrent=%.0f\n", prefix, entry->current_raw);
            fprintf(f, "%scapacity=%u\n", prefix, entry->capacity_mah);
            fprintf(f, "%sremaining=%u\n", prefix, (unsigned)entry->remaining_pct);
        } else {
            fprintf(f, "%svoltage=\n", prefix);
            fprintf(f, "%scurrent=\n", prefix);
            fprintf(f, "%scapacity=\n", prefix);
            fprintf(f, "%sremaining=\n", prefix);
        }

        if (entry->has_gps) {
            fprintf(f, "%slatitude=%.7f\n", prefix, entry->latitude_deg);
            fprintf(f, "%slongitude=%.7f\n", prefix, entry->longitude_deg);
            fprintf(f, "%sgroundspeed=%.0f\n", prefix, entry->groundspeed_raw);
            fprintf(f, "%sheading=%.2f\n", prefix, entry->heading_deg);
            fprintf(f, "%saltitude=%.2f\n", prefix, entry->altitude_m);
            fprintf(f, "%ssats=%u\n", prefix, (unsigned)entry->sats);
        } else {
            fprintf(f, "%slatitude=\n", prefix);
            fprintf(f, "%slongitude=\n", prefix);
            fprintf(f, "%sgroundspeed=\n", prefix);
            fprintf(f, "%sheading=\n", prefix);
            fprintf(f, "%saltitude=\n", prefix);
            fprintf(f, "%ssats=\n", prefix);
        }

        if (entry->has_any || entry->frames_rc || entry->frames_gps ||
            entry->frames_battery || entry->frames_link_stats || entry->frames_other) {
            double rc_kframes   = (double)entry->frames_rc / 1000.0;
            double gps_kframes  = (double)entry->frames_gps / 1000.0;
            double bat_kframes  = (double)entry->frames_battery / 1000.0;
            double lnk_kframes  = (double)entry->frames_link_stats / 1000.0;
            double oth_kframes  = (double)entry->frames_other / 1000.0;
            fprintf(f, "%src_kframes=%.1f\n", prefix, rc_kframes);
            fprintf(f, "%sgps_kframes=%.1f\n", prefix, gps_kframes);
            fprintf(f, "%sbat_kframes=%.1f\n", prefix, bat_kframes);
            fprintf(f, "%slnk_kframes=%.1f\n", prefix, lnk_kframes);
            fprintf(f, "%sother_kframes=%.1f\n", prefix, oth_kframes);

            if (entry->last_frame.tv_sec || entry->last_frame.tv_nsec) {
                long long age_ms = diff_ms(&now_ts, &entry->last_frame);
                if (age_ms < 0) age_ms = 0;
                fprintf(f, "%slast_frame_age_ms=%lld\n", prefix, age_ms);
            } else {
                fprintf(f, "%slast_frame_age_ms=\n", prefix);
            }
        }

        if (entry->has_status) {
            fprintf(f, "%sarmed=%d\n", prefix, entry->armed);
            fprintf(f, "%smode_flags=0x%08X\n", prefix, entry->flight_mode_flags);

            unsigned int rssi_pct = (unsigned int)(((float)entry->rssi_raw / 1023.0f) * 100.0f);
            if (rssi_pct > 100) rssi_pct = 100;
            fprintf(f, "%sradio_rssi=%u\n", prefix, rssi_pct);
        } else {
            fprintf(f, "%sarmed=\n", prefix);
            fprintf(f, "%smode_flags=\n", prefix);
            fprintf(f, "%sradio_rssi=\n", prefix);
        }

        if (entry->has_home) {
            fprintf(f, "%shome_dist=%.1f\n", prefix, entry->home_dist_m);
            fprintf(f, "%shome_dir=%.1f\n", prefix, entry->home_dir_deg);
        } else {
            fprintf(f, "%shome_dist=\n", prefix);
            fprintf(f, "%shome_dir=\n", prefix);
        }

        if (entry->has_baro) {
            fprintf(f, "%sbaro_alt=%.1f\n", prefix, entry->baro_altitude_m);
            fprintf(f, "%svario=%.1f\n", prefix, entry->vario_m_s);
        } else {
            fprintf(f, "%sbaro_alt=\n", prefix);
            fprintf(f, "%svario=\n", prefix);
        }

        if (entry->has_attitude) {
            fprintf(f, "%sroll=%.1f\n", prefix, entry->roll_deg);
            fprintf(f, "%spitch=%.1f\n", prefix, entry->pitch_deg);
        } else {
            fprintf(f, "%sroll=\n", prefix);
            fprintf(f, "%spitch=\n", prefix);
        }

        if (entry->armed_accumulated_s > 0 || entry->armed) {
            double flight_time = entry->armed_accumulated_s;
            if (entry->armed) {
                flight_time += (now_s - entry->armed_start_time);
            }
            fprintf(f, "%sflight_time_s=%.1f\n", prefix, flight_time);
        } else {
            fprintf(f, "%sflight_time_s=\n", prefix);
        }
    }

    fclose(f);
    log->last_write = now_ts;
}

static void telemetry_update_crsf(const config_t *cfg, telemetry_log_state_t *log, const state_t *st,
                            crsf_source_t src, uint8_t type, const uint8_t *payload,
                            size_t payload_len)
{
    if (!log->enabled || src >= CRSF_SRC_MAX) return;

    telemetry_entry_t *entry = &log->entries[src];
    entry->has_any = true;
    get_mono(&entry->last_frame);

    if (type == 0x08 && payload_len >= 8) {
        uint16_t voltage_raw = ((uint16_t)payload[0] << 8) | (uint16_t)payload[1];
        uint16_t current_raw = ((uint16_t)payload[2] << 8) | (uint16_t)payload[3];
        uint32_t capacity = ((uint32_t)payload[4] << 16) | ((uint32_t)payload[5] << 8) | (uint32_t)payload[6];
        uint8_t remaining = payload[7];

        entry->voltage_v = (double)voltage_raw / 10.0;
        entry->current_raw = (double)current_raw;
        entry->capacity_mah = capacity;
        entry->remaining_pct = remaining;
        entry->has_battery = true;
        entry->frames_battery++;
    } else if (type == 0x02 && payload_len >= 15) {
        int32_t lat_raw = (int32_t)((uint32_t)payload[0] << 24 | (uint32_t)payload[1] << 16 |
                                    (uint32_t)payload[2] << 8 | (uint32_t)payload[3]);
        int32_t lon_raw = (int32_t)((uint32_t)payload[4] << 24 | (uint32_t)payload[5] << 16 |
                                    (uint32_t)payload[6] << 8 | (uint32_t)payload[7]);
        uint16_t groundspeed = ((uint16_t)payload[8] << 8) | (uint16_t)payload[9];
        uint16_t heading = ((uint16_t)payload[10] << 8) | (uint16_t)payload[11];
        uint16_t altitude = ((uint16_t)payload[12] << 8) | (uint16_t)payload[13];
        uint8_t sats = payload[14];

        entry->latitude_deg = (double)lat_raw / 1e7;
        entry->longitude_deg = (double)lon_raw / 1e7;
        entry->groundspeed_raw = (double)groundspeed;
        entry->heading_deg = (double)heading / 100.0;
        entry->altitude_m = (double)((int)altitude - 1000);
        entry->sats = sats;
        entry->has_gps = true;
        entry->frames_gps++;
    } else if (type == 0x16) {
        entry->frames_rc++;
    } else if (type == 0x14) {
        entry->frames_link_stats++;
    } else {
        entry->frames_other++;
    }

    telemetry_log_write(cfg, log, st);
}

static void telemetry_update_msp(const config_t *cfg, telemetry_log_state_t *log, const state_t *st,
                           crsf_source_t src, uint8_t cmd, const uint8_t *payload,
                           size_t payload_len)
{
    if (!log->enabled || src >= CRSF_SRC_MAX) return;

    telemetry_entry_t *entry = &log->entries[src];
    entry->has_any = true;
    get_mono(&entry->last_frame);

    if (cmd == MSP_ANALOG && payload_len >= 7) {
        // payload: vbat(1), powerMeterSum(2), rssi(2), amperage(2)
        uint8_t vbat = payload[0];
        uint16_t mah = ((uint16_t)payload[2] << 8) | (uint16_t)payload[1]; // Little endian? usually MSP is. actually bytes are LSB, MSB.
        // Wait, MSP is LE. payload[1] is LSB, payload[2] is MSB.
        uint16_t rssi = ((uint16_t)payload[4] << 8) | (uint16_t)payload[3];
        uint16_t amperage = ((uint16_t)payload[6] << 8) | (uint16_t)payload[5];

        entry->voltage_v = (double)vbat / 10.0;
        entry->current_raw = (double)amperage;
        if (!entry->capacity_mah) entry->capacity_mah = mah; // Prefer MSP_BATTERY_STATE if available
        entry->rssi_raw = rssi;
        entry->has_battery = true;
        entry->has_status = true; // for rssi
        entry->frames_battery++;
    } else if (cmd == MSP_BATTERY_STATE && payload_len >= 5) {
        // payload: amperage(2), capacity(2), voltage(1)
        uint16_t amperage = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
        uint16_t capacity = (uint16_t)payload[2] | ((uint16_t)payload[3] << 8);
        uint8_t voltage = payload[4];

        // entry->voltage_v = (double)voltage / 10.0; // Avoid conflict with MSP_ANALOG
        // entry->current_raw = (double)amperage; // Avoid conflict with MSP_ANALOG
        entry->capacity_mah = capacity;
        entry->has_battery = true;
        entry->frames_battery++;
    } else if ((cmd == MSP_STATUS || cmd == MSP_STATUS_EX) && payload_len >= 10) {
        // cycleTime(2), i2c_errors(2), sensor(2), flag(4)
        uint32_t flags = (uint32_t)payload[6] | ((uint32_t)payload[7]<<8) | ((uint32_t)payload[8]<<16) | ((uint32_t)payload[9]<<24);

        entry->flight_mode_flags = flags;
        entry->armed = (flags & 1); // Box 0 is usually ARM
        entry->has_status = true;
        entry->frames_other++;
    } else if (cmd == MSP_RAW_GPS && payload_len >= 16) {
        // fix(1), numSat(1), lat(4), lon(4), alt(2), speed(2), ground_course(2)
        uint8_t sats = payload[1];
        int32_t lat = (int32_t)((uint32_t)payload[2] | ((uint32_t)payload[3]<<8) | ((uint32_t)payload[4]<<16) | ((uint32_t)payload[5]<<24));
        int32_t lon = (int32_t)((uint32_t)payload[6] | ((uint32_t)payload[7]<<8) | ((uint32_t)payload[8]<<16) | ((uint32_t)payload[9]<<24));
        int16_t alt = (int16_t)(payload[10] | (payload[11]<<8));
        uint16_t speed = (uint16_t)(payload[12] | (payload[13]<<8));
        uint16_t course = (uint16_t)(payload[14] | (payload[15]<<8));

        entry->latitude_deg = (double)lat / 1e7;
        entry->longitude_deg = (double)lon / 1e7;
        entry->altitude_m = (double)alt; // meters (GPS)
        entry->groundspeed_raw = (double)speed; // cm/s
        entry->heading_deg = (double)course / 10.0;
        entry->sats = sats;
        entry->has_gps = true;
        entry->frames_gps++;
    } else if (cmd == MSP_COMP_GPS && payload_len >= 4) {
        // distanceToHome(2), directionToHome(2)
        uint16_t dist = (uint16_t)payload[0] | ((uint16_t)payload[1]<<8);
        uint16_t dir = (uint16_t)payload[2] | ((uint16_t)payload[3]<<8);

        entry->home_dist_m = (double)dist;
        entry->home_dir_deg = (double)dir;
        entry->has_home = true;
        entry->frames_gps++;
    } else if (cmd == MSP_ALTITUDE && payload_len >= 6) {
        // EstAlt(4) cm, Vario(2) cm/s
        int32_t alt_cm = (int32_t)((uint32_t)payload[0] | ((uint32_t)payload[1]<<8) | ((uint32_t)payload[2]<<16) | ((uint32_t)payload[3]<<24));
        int16_t vario_cms = (int16_t)(payload[4] | (payload[5]<<8));

        entry->baro_altitude_m = (double)alt_cm / 100.0;
        entry->vario_m_s = (double)vario_cms / 100.0;
        entry->has_baro = true;
        entry->frames_other++;
    } else if (cmd == MSP_ATTITUDE && payload_len >= 6) {
        // roll(2), pitch(2), yaw(2)
        int16_t roll = (int16_t)(payload[0] | (payload[1]<<8));
        int16_t pitch = (int16_t)(payload[2] | (payload[3]<<8));
        int16_t yaw = (int16_t)(payload[4] | (payload[5]<<8));

        entry->roll_deg = (double)roll / 10.0;
        entry->pitch_deg = (double)pitch / 10.0;
        entry->heading_deg = (double)yaw / 10.0;
        entry->has_attitude = true;
        entry->frames_other++;
    } else {
        entry->frames_other++;
    }

    telemetry_log_write(cfg, log, st);
}

/* CRSF forwarding */
static void crsf_forward_reset(state_t *st)
{
    crsf_stream_reset(&st->crsf_uart_out);
}

static void crsf_forward_send(const config_t *cfg, state_t *st, const crsf_stream_t *s)
{
    uint8_t len_field = s->frame[1];
    size_t total = (size_t)len_field + 2;

    if (len_field < 2 || total != s->len || total < 4 || total > sizeof(s->frame)) {
        st->drops_uart_to_net += (uint64_t)s->len;
        vlog(2, "CRSF: invalid length field len=%u frame_len=%zu, dropping", len_field, s->len);
        return;
    }

    size_t crc_off = total - 1;
    uint8_t expected_crc = s->frame[crc_off];
    uint8_t calc_crc = crc8_d5(s->frame + 2, (size_t)len_field - 1);
    if (calc_crc != expected_crc) {
        st->drops_uart_to_net += (uint64_t)s->len;
        vlog(2, "CRSF: CRC mismatch calc=0x%02X expected=0x%02X, dropping", calc_crc, expected_crc);
        return;
    }

    if (!st->udp_peer_set) {
        st->drops_uart_to_net += (uint64_t)s->len;
        return;
    }

    if (cfg->telemetry_coalesce) {
        uart_forward_with_coalesce(cfg, st, s->frame, s->len);
        return;
    }

    if (s->len > st->udp_out_cap) {
        st->drops_uart_to_net += (uint64_t)s->len;
        vlog(2, "CRSF: frame too large (%zu > %zu), dropping", s->len, st->udp_out_cap);
        return;
    }

    if (st->udp_out_len > 0) {
        udp_flush_if_ready(cfg, st, true, "crsf_waiting_flush");
        if (st->udp_out_len > 0) {
            st->drops_uart_to_net += (uint64_t)s->len;
            vlog(2, "CRSF: pending datagram not sent, dropping frame");
            return;
        }
    }

    memcpy(st->udp_out, s->frame, s->len);
    st->udp_out_len = s->len;
    udp_flush_if_ready(cfg, st, true, "crsf_frame");
}

static void crsf_forward_feed(const config_t *cfg, state_t *st, const uint8_t *data, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t b = data[i];
        crsf_stream_t *s = &st->crsf_uart_out;

        if (s->len == 0) {
            s->frame[0] = b;
            s->len = 1;
            s->expected = 0;
            continue;
        }

        if (s->len == 1) {
            s->frame[1] = b;
            s->len = 2;
            size_t total = (size_t)b + 2;
            if (total < 4 || total > sizeof(s->frame)) {
                crsf_forward_reset(st);
            } else {
                s->expected = total;
            }
            continue;
        }

        if (s->len < sizeof(s->frame)) {
            s->frame[s->len] = b;
        }
        s->len++;

        if (s->expected && s->len == s->expected) {
            crsf_forward_send(cfg, st, s);
            crsf_forward_reset(st);
        } else if (s->len >= sizeof(s->frame)) {
            crsf_forward_reset(st);
        }
    }
}

static void uart_forward_with_coalesce(const config_t *cfg, state_t *st,
                                       const uint8_t *data, size_t n)
{
    size_t remaining = n;
    size_t offset = 0;

    while (remaining > 0) {
        size_t available = st->udp_out_cap - st->udp_out_len;
        if (available == 0) {
            udp_flush_if_ready(cfg, st, true, "buffer_full");
            available = st->udp_out_cap - st->udp_out_len;
            if (available == 0) {
                st->drops_uart_to_net += (uint64_t)remaining;
                break;
            }
        }

        size_t chunk = remaining < available ? remaining : available;
        memcpy(st->udp_out + st->udp_out_len, data + offset, chunk);
        st->udp_out_len += chunk;
        remaining -= chunk;
        offset += chunk;
    }

    bool force = (cfg->telemetry_coalesce == 0);
    udp_flush_if_ready(cfg, st, force,
        st->udp_out_len >= (size_t)cfg->udp_coalesce_bytes ? "size_threshold" : "pending");
}

/* --------------------------------- main ------------------------------------- */
int main(int argc, char **argv){
    const char *conf_path = DEFAULT_CONF;

    for (int i=1;i<argc;i++){
        if (!strcmp(argv[i],"-c") && i+1<argc) { conf_path=argv[++i]; }
        else if (argv[i][0]=='-' && argv[i][1]=='v') {
            g_verbosity++;
        } else if(!strcmp(argv[i],"-h")||!strcmp(argv[i],"--help")){
            fprintf(stderr,
                "Usage: %s [-c /path/to/conf] [-v]\n"
                "  -c FILE   Path to config (default %s)\n"
                "  -v        Verbose stats once per second (enables CRSF output when configured)\n",
                argv[0], DEFAULT_CONF);
            return 0;
        }
    }

    config_t cfg;
    if(parse_config(conf_path,&cfg)<0){
        fprintf(stderr,"Failed to read config: %s (%s)\n", conf_path, strerror(errno));
        return 1;
    }
    vlog(1, "Loaded config: uart_backend=%s",
         (cfg.uart_backend==UART_TTY?"tty":"stdio"));

    if (cfg.telemetry_proto != PROTO_OFF) {
        const char *pname = "Unknown";
        if (cfg.telemetry_proto == PROTO_CRSF) pname = "CRSF";
        else if (cfg.telemetry_proto == PROTO_MSP) pname = "MSP";
        else if (cfg.telemetry_proto == PROTO_MAV) pname = "MAVLink";

        vlog(1, "Telemetry enabled: %s (Log: %s, Interval: %dms, Rate: %dHz)",
             pname, cfg.telemetry_log_enable ? "On" : "Off",
             cfg.telemetry_log_interval, cfg.telemetry_msp_rate);
    } else {
        vlog(1, "Telemetry disabled");
    }

    state_t st; memset(&st,0,sizeof(st));
    st.fd_uart=st.fd_net=-1; st.fd_stdout=-1;
    st.epfd=epoll_create1(0); if(st.epfd<0){ perror("epoll_create1"); return 1; }

    telemetry_log_init(&st.log_state, &cfg);

    telemetry_log_ctx_t log_ctx = { .cfg = &cfg, .log = &st.log_state, .st = &st };
    bool telemetry_enabled = (cfg.telemetry_proto != PROTO_OFF) && (g_verbosity || cfg.telemetry_log_enable);
    telemetry_monitor_t telemetry;
    telemetry_monitor_init(&telemetry, telemetry_enabled, cfg.telemetry_proto, telemetry_log_on_crsf_frame, &log_ctx, telemetry_log_on_msp_frame, &log_ctx);

    size_t udp_out_cap = cfg.udp_max_datagram>0?(size_t)cfg.udp_max_datagram:1200;
    st.udp_out=(uint8_t*)malloc(udp_out_cap);
    st.udp_out_len=0;
    st.udp_out_cap=udp_out_cap;
    if(!st.udp_out){
        st.udp_out_cap=0;
        fprintf(stderr,"Failed to allocate UDP buffer (%s)\n", strerror(errno));
        return 1;
    }
    if(ring_init(&st.uart_out,cfg.tx_buf)<0){
        fprintf(stderr,"Failed to allocate ring buffer (%s)\n", strerror(errno));
        free(st.udp_out); st.udp_out=NULL;
        return 1;
    }

    crsf_forward_reset(&st);

    struct sigaction sa={0}; sa.sa_handler=on_sighup; sigaction(SIGHUP,&sa,NULL);
    sa.sa_handler=on_sigterm; sigaction(SIGINT,&sa,NULL); sigaction(SIGTERM,&sa,NULL);

    if(reopen_everything(&cfg,&st)<0){
        fprintf(stderr,"Failed to open UART/STDIO/network (%s)\n", strerror(errno));
        return 1;
    }

    uint8_t *buf_uart=malloc(cfg.rx_buf), *buf_net=malloc(cfg.rx_buf);
    size_t rx_buf_cap = cfg.rx_buf;
    if(!buf_uart||!buf_net){ fprintf(stderr,"OOM\n"); free(buf_uart); free(buf_net); return 1; }

    st.running=true; get_mono(&st.last_uart_rx);
    reset_stats_window(&st);

    while(st.running && !g_stop){
        if(g_reload){
            vlog(1, "SIGHUP: reloading %s", conf_path);
            g_reload=0;
            config_t newcfg;
            if(parse_config(conf_path,&newcfg)==0){
                config_t oldcfg = cfg;

                size_t desired_udp_cap = newcfg.udp_max_datagram>0?(size_t)newcfg.udp_max_datagram:1200;
                bool udp_resize = desired_udp_cap != st.udp_out_cap;
                uint8_t *new_udp_out = NULL;
                if(udp_resize){
                    new_udp_out = (uint8_t*)malloc(desired_udp_cap);
                    if(!new_udp_out){
                        vlog(1, "SIGHUP: UDP buffer alloc failed (%s), keeping previous config", strerror(errno));
                        continue;
                    }
                }

                size_t desired_rx = newcfg.rx_buf>0?newcfg.rx_buf:1;
                bool rx_resize = desired_rx != rx_buf_cap;
                uint8_t *new_buf_uart=NULL, *new_buf_net=NULL;
                if(rx_resize){
                    new_buf_uart=(uint8_t*)malloc(desired_rx);
                    new_buf_net=(uint8_t*)malloc(desired_rx);
                    if(!new_buf_uart||!new_buf_net){
                        int err = errno;
                        free(new_buf_uart);
                        free(new_buf_net);
                        if(new_udp_out) free(new_udp_out);
                        vlog(1, "SIGHUP: RX buffer alloc failed (%s), keeping previous config", strerror(err));
                        continue;
                    }
                }

                if(reopen_everything(&newcfg,&st)<0){
                    int err = errno;
                    vlog(1, "SIGHUP: reopen failed (%s), attempting to restore previous config", strerror(err));
                    if(reopen_everything(&oldcfg,&st)<0){
                        int restore_err = errno;
                        vlog(0, "SIGHUP: failed to restore previous config (%s), stopping", strerror(restore_err));
                        if(rx_resize){ free(new_buf_uart); free(new_buf_net); }
                        if(new_udp_out) free(new_udp_out);
                        st.running=false;
                        break;
                    }
                    cfg = oldcfg;
                    if(rx_resize){ free(new_buf_uart); free(new_buf_net); }
                    if(new_udp_out) free(new_udp_out);
                    reset_stats_window(&st);
                    continue;
                }

                cfg = newcfg;

                telemetry_monitor_set_enabled(
                    &telemetry, (cfg.telemetry_proto != PROTO_OFF) && (g_verbosity || cfg.telemetry_log_enable), cfg.telemetry_proto);
                telemetry_log_init(&st.log_state, &cfg);

                if(rx_resize){
                    free(buf_uart);
                    free(buf_net);
                    buf_uart = new_buf_uart;
                    buf_net = new_buf_net;
                    rx_buf_cap = desired_rx;
                }

                if(new_udp_out){
                    uint8_t *old_udp = st.udp_out;
                    st.udp_out = new_udp_out;
                    st.udp_out_cap = desired_udp_cap;
                    st.udp_out_len = 0;
                    st.udp_wait_writable = false;
                    free(old_udp);
                } else {
                    st.udp_out_cap = desired_udp_cap;
                    st.udp_out_len = 0;
                    st.udp_wait_writable = false;
                }

                crsf_forward_reset(&st);

                get_mono(&st.last_uart_rx);
                reset_stats_window(&st);
                vlog(1, "SIGHUP: reload successful (uart_backend=%s)",
                     (cfg.uart_backend==UART_TTY?"tty":"stdio"));
            } else {
                vlog(1, "SIGHUP: parse failed, keeping previous config");
            }
        }

        int timeout_ms=500;
        if (cfg.telemetry_proto == PROTO_MSP) {
            struct timespec now; get_mono(&now);
            long long since_poll = diff_ms(&now, &st.last_msp_poll);
            long long poll_rate = 1000 / cfg.telemetry_msp_rate;
            if (since_poll >= poll_rate) {
                // Time to poll
                st.last_msp_poll = now;
                msp_send_query(&st.uart_out, MSP_ANALOG);
                msp_send_query(&st.uart_out, MSP_STATUS_EX);
                msp_send_query(&st.uart_out, MSP_RAW_GPS);
                msp_send_query(&st.uart_out, MSP_COMP_GPS);
                msp_send_query(&st.uart_out, MSP_ALTITUDE);
                msp_send_query(&st.uart_out, MSP_ATTITUDE);
                msp_send_query(&st.uart_out, MSP_BATTERY_STATE);

                timeout_ms = 0; // Wake up immediately to write
            } else {
                long long remain = poll_rate - since_poll;
                if (remain < timeout_ms) timeout_ms = (int)remain;
            }
        }

        if(st.udp_out_len>0 && cfg.udp_coalesce_idle_ms>0){
            struct timespec now; get_mono(&now);
            long long waited=diff_ms(&now,&st.last_uart_rx);
            long long remain=cfg.udp_coalesce_idle_ms - waited;
            if(remain<0) remain=0;
            if(remain<timeout_ms) timeout_ms=(int)remain;
        }

        if(g_verbosity){
            struct timespec now; get_mono(&now);
            if(st.last_stats_report.tv_sec!=0 || st.last_stats_report.tv_nsec!=0){
                long long since = diff_ms(&now,&st.last_stats_report);
                long long remain = 1000 - since;
                if(remain<0) remain=0;
                if(remain<timeout_ms) timeout_ms=(int)remain;
            } else if(timeout_ms>1000){
                timeout_ms=1000;
            }
        }

        if(st.fd_net>=0){
            uint32_t net_events = EPOLLIN | (st.udp_wait_writable ? EPOLLOUT : 0);
            mod_ep(st.epfd, st.fd_net, net_events);
        }

        if(cfg.uart_backend==UART_TTY){
            uint32_t uart_events = EPOLLIN | (st.uart_out.len>0?EPOLLOUT:0);
            mod_ep(st.epfd, st.fd_uart, uart_events);
        } else {
            if(st.uart_out.len>0 && !st.stdout_registered){ add_ep(st.epfd, STDOUT_FILENO, EPOLLOUT); st.stdout_registered=true; }
            else if(st.uart_out.len==0 && st.stdout_registered){ del_ep(st.epfd, STDOUT_FILENO); st.stdout_registered=false; }
        }

        struct epoll_event evs[MAX_EVENTS]; int n=epoll_wait(st.epfd, evs, MAX_EVENTS, timeout_ms);
        if(n<0){ if(errno==EINTR) continue; break; }

        if(st.udp_out_len>0 && cfg.udp_coalesce_idle_ms>0){
            struct timespec now; get_mono(&now);
            if(diff_ms(&now,&st.last_uart_rx) >= cfg.udp_coalesce_idle_ms){
                udp_flush_if_ready(&cfg,&st,true,"idle_timeout");
            }
        }

        for(int i=0;i<n;i++){
            int fd=evs[i].data.fd; uint32_t ev=evs[i].events;

            if(fd==st.fd_uart && (ev&EPOLLIN)){
                ssize_t r=read(st.fd_uart,(void*)buf_uart,cfg.rx_buf);
                if(r>0){
                    vlog(3, "UART rx: %zd bytes", r);
                    bool telemetry_mode = cfg.telemetry_proto != PROTO_OFF;

                    get_mono(&st.last_uart_rx);
                    if (telemetry.enabled) {
                        telemetry_monitor_feed(&telemetry, CRSF_FROM_UART, buf_uart, (size_t)r);
                    }

                    bool use_crsf_forward = telemetry_mode && (cfg.telemetry_proto == PROTO_CRSF);

                    if (use_crsf_forward) {
                        crsf_forward_feed(&cfg, &st, buf_uart, (size_t)r);
                    } else {
                        uart_forward_with_coalesce(&cfg, &st, buf_uart, (size_t)r);
                    }
                }
            }

            if(fd==st.fd_net && (ev&EPOLLIN)){
                struct sockaddr_in from; socklen_t flen=sizeof(from);
                ssize_t r=recvfrom(st.fd_net, buf_net, cfg.rx_buf, 0,(struct sockaddr*)&from,&flen);
                if(r>0){
                    if (telemetry.enabled) {
                        telemetry_monitor_feed(&telemetry, CRSF_FROM_UDP, buf_net, (size_t)r);
                    }
                    if(!cfg.udp_peer_addr[0]){
                        bool changed = !st.udp_peer_set ||
                            st.udp_peer.sin_addr.s_addr!=from.sin_addr.s_addr ||
                            st.udp_peer.sin_port!=from.sin_port;
                        if(changed){
                            st.udp_peer = from; st.udp_peer_set=true;
                            char ipbuf[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET,&from.sin_addr,ipbuf,sizeof(ipbuf));
                            vlog(1, "UDP: learned peer %s:%d", ipbuf, ntohs(from.sin_port));
                        }
                    }
                    int outfd = (cfg.uart_backend==UART_STDIO)? STDOUT_FILENO : st.fd_uart;
                    ssize_t w=write(outfd, buf_net, (size_t)r);
                    if(w>0){
                        st.bytes_net_to_uart+=(uint64_t)w; st.pkts_net_to_uart+=1;
                        if(w<r){
                            size_t rem=(size_t)r-(size_t)w;
                            size_t wr=ring_write(&st.uart_out, buf_net+w, rem);
                            if(wr<rem) st.drops_net_to_uart+=(uint64_t)(rem-wr);
                            if(cfg.uart_backend==UART_STDIO){
                                if(!st.stdout_registered){ add_ep(st.epfd, STDOUT_FILENO, EPOLLOUT); st.stdout_registered=true; }
                            } else {
                                mod_ep(st.epfd, st.fd_uart, EPOLLIN|EPOLLOUT);
                            }
                        }
                    } else if(w<0 && (errno==EAGAIN||errno==EWOULDBLOCK)){
                        size_t wr=ring_write(&st.uart_out, buf_net, (size_t)r);
                        if(wr<(size_t)r) st.drops_net_to_uart+=(uint64_t)((size_t)r-wr);
                        if(cfg.uart_backend==UART_STDIO){
                            if(!st.stdout_registered){ add_ep(st.epfd, STDOUT_FILENO, EPOLLOUT); st.stdout_registered=true; }
                        } else {
                            mod_ep(st.epfd, st.fd_uart, EPOLLIN|EPOLLOUT);
                        }
                    }
                }
            }

            if(fd==st.fd_net && (ev&EPOLLOUT)){
                if(st.udp_out_len>0) udp_flush_if_ready(&cfg,&st,true,"retry");
            }

            if(cfg.uart_backend==UART_TTY && fd==st.fd_uart && (ev&EPOLLOUT)){
                if(st.uart_out.len>0){ ssize_t w=write_from_ring_fd(st.fd_uart,&st.uart_out); if(w>0) st.bytes_net_to_uart+=(uint64_t)w; }
                uint32_t want=EPOLLIN | (st.uart_out.len?EPOLLOUT:0); mod_ep(st.epfd, st.fd_uart, want);
            }

            if(cfg.uart_backend==UART_STDIO && st.stdout_registered && fd==STDOUT_FILENO && (ev&EPOLLOUT)){
                if(st.uart_out.len>0){ ssize_t w=write_from_ring_fd(STDOUT_FILENO,&st.uart_out); if(w>0) st.bytes_net_to_uart+=(uint64_t)w; }
                if(st.uart_out.len==0){ del_ep(st.epfd, STDOUT_FILENO); st.stdout_registered=false; }
            }
        }

        udp_flush_if_ready(&cfg,&st,false,
            st.udp_out_len >= (size_t)cfg.udp_coalesce_bytes ? "size_threshold" : "pending");
        maybe_print_stats(&st);
        telemetry_monitor_maybe_report(&telemetry);
        telemetry_log_write(&cfg, &st.log_state, &st);
    }

    maybe_print_stats(&st);
    telemetry_monitor_maybe_report(&telemetry);
    vlog(1, "Exiting");

    if(cfg.uart_backend==UART_TTY && st.fd_uart>=0) del_ep(st.epfd,st.fd_uart), close_fd(&st.fd_uart);
    if(st.fd_net>=0) del_ep(st.epfd,st.fd_net), close_fd(&st.fd_net);
    if(st.stdout_registered){ del_ep(st.epfd, STDOUT_FILENO); }
    if(st.epfd>=0) close(st.epfd);
    free(buf_uart); free(buf_net);
    ring_free(&st.uart_out);
    free(st.udp_out);
    return 0;
}
