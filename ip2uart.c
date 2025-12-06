// ip2uart.c — TTY/STDIO <-> UDP bridge for embedded Linux
// - UART side selectable: uart_backend=tty | stdio
// - UDP: static peer (fire-and-forget), accepts from any sender
// - UDP coalescing: size threshold + short idle before send
// - Short-write safe: ring buffers for both directions (non-blocking)
// - SIGHUP: reload /etc/ip2uart.conf and reopen resources
// - Verbose logging: -v prints one-line stats once per second
// SPDX-License-Identifier: MIT

#define _GNU_SOURCE
#include <arpa/inet.h>
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
typedef struct {
    // Selectors
    uart_backend_t uart_backend;   // tty | stdio

    // CRSF parser
    int  crsf_detect;              // 0 | 1
    int  crsf_log;                 // 0 | 1
    char crsf_log_path[256];
    int  crsf_log_rate_ms;         // >= 0
    int  crsf_coalesce;            // 0 | 1

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
} crsf_monitor_t;

typedef struct {
    bool enabled;
    bool has_battery;
    bool has_gps;
    struct timespec last_write;

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
} crsf_log_state_t;

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
    crsf_log_state_t crsf_log;

    // stats
    uint64_t bytes_uart_to_net, bytes_net_to_uart;
    uint64_t pkts_uart_to_net,  pkts_net_to_uart;
    uint64_t drops_uart_to_net, drops_net_to_uart;

    // timers
    struct timespec last_uart_rx; // for UDP idle
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
static void trim(char *s){ if(!s) return; size_t n=strlen(s),i=0,j=n; while(i<n&&(s[i]==' '||s[i]=='\t'||s[i]=='\r'||s[i]=='\n')) i++; while(j>i&&(s[j-1]==' '||s[j-1]=='\t'||s[j-1]=='\r'||s[j-1]=='\n')) j--; if(i>0) memmove(s,s+i,j-i); s[j-i]=0; }
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
    cfg->crsf_detect = 0;
    cfg->crsf_log = 0;
    strcpy(cfg->crsf_log_path, "/tmp/crsf_log.msg");
    cfg->crsf_log_rate_ms = 100;
    cfg->crsf_coalesce = 0;

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
        trim(key); trim(val); if(!*key) continue;

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
        else if(!strcmp(key,"crsf_detect")) cfg->crsf_detect=atoi(val);
        else if(!strcmp(key,"crsf_log")) cfg->crsf_log=atoi(val);
        else if(!strcmp(key,"crsf_log_path")){
            strncpy(cfg->crsf_log_path, val, sizeof(cfg->crsf_log_path) - 1);
            cfg->crsf_log_path[sizeof(cfg->crsf_log_path) - 1] = 0;
        }
        else if(!strcmp(key,"crsf_log_rate_ms")) cfg->crsf_log_rate_ms=atoi(val);
        else if(!strcmp(key,"crsf_coalesce")) cfg->crsf_coalesce=atoi(val);
    }
    fclose(f);

    if (cfg->udp_max_datagram <= 0) cfg->udp_max_datagram = 1200;
    if (cfg->udp_coalesce_bytes <= 0 || cfg->udp_coalesce_bytes > cfg->udp_max_datagram)
        cfg->udp_coalesce_bytes = cfg->udp_max_datagram;
    if (cfg->udp_coalesce_idle_ms < 0) cfg->udp_coalesce_idle_ms = 0;
    if (cfg->rx_buf == 0) cfg->rx_buf = 1024;
    if (cfg->tx_buf == 0) cfg->tx_buf = 65536;
    if (cfg->crsf_log_rate_ms <= 0) cfg->crsf_log_rate_ms = 100;
    if (!cfg->crsf_log_path[0]) strcpy(cfg->crsf_log_path, "/tmp/crsf_log.msg");
    cfg->crsf_coalesce = cfg->crsf_coalesce ? 1 : 0;

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
static void crsf_monitor_init(crsf_monitor_t *m, bool enabled)
{
    memset(m, 0, sizeof(*m));
    m->enabled = enabled;

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
    crsf_monitor_init(m, enabled);
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

    size_t crc_off = total - 1;
    uint8_t expected_crc = s->frame[crc_off];
    uint8_t calc_crc = crc8_d5(s->frame + 2, (size_t)len_field - 1);
    if (calc_crc != expected_crc) {
        m->invalid_frames[src]++;
        return;
    }

    uint8_t type = s->frame[2];
    m->type_counts[src][type] += 1;

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

/* CRSF logging */
static void crsf_log_reset(crsf_log_state_t *log)
{
    memset(log, 0, sizeof(*log));
}

static void crsf_log_apply_config(crsf_log_state_t *log, const config_t *cfg)
{
    bool new_enabled = cfg->crsf_detect && cfg->crsf_log && cfg->crsf_log_path[0];

    if (!new_enabled) {
        crsf_log_reset(log);
        return;
    }

    if (!log->enabled) {
        log->has_battery = false;
        log->has_gps = false;
        log->last_write.tv_sec = 0;
        log->last_write.tv_nsec = 0;
    }

    log->enabled = true;
}

static void crsf_log_maybe_write(const config_t *cfg, crsf_log_state_t *log)
{
    if (!log->enabled) return;
    if (!log->has_battery && !log->has_gps) return;

    struct timespec now;
    get_mono(&now);
    if (log->last_write.tv_sec || log->last_write.tv_nsec) {
        if (diff_ms(&now, &log->last_write) < cfg->crsf_log_rate_ms) return;
    }

    FILE *f = fopen(cfg->crsf_log_path, "w");
    if (!f) {
        vlog(2, "CRSF log: failed to open %s (%s)", cfg->crsf_log_path, strerror(errno));
        return;
    }

    if (log->has_battery) {
        fprintf(f, "voltage=%.1f\n", log->voltage_v);
        fprintf(f, "current=%.0f\n", log->current_raw);
        fprintf(f, "capacity=%u\n", log->capacity_mah);
        fprintf(f, "remaining=%u\n", (unsigned)log->remaining_pct);
    }

    if (log->has_gps) {
        fprintf(f, "latitude=%.7f\n", log->latitude_deg);
        fprintf(f, "longitude=%.7f\n", log->longitude_deg);
        fprintf(f, "groundspeed=%.0f\n", log->groundspeed_raw);
        fprintf(f, "heading=%.2f\n", log->heading_deg);
        fprintf(f, "altitude=%.2f\n", log->altitude_m);
        fprintf(f, "sats=%u\n", (unsigned)log->sats);
    }

    fclose(f);
    log->last_write = now;
}

static void crsf_log_update(const config_t *cfg, state_t *st, uint8_t type, const uint8_t *payload, size_t payload_len)
{
    if (!st->crsf_log.enabled) return;

    if (type == 0x08 && payload_len >= 8) {
        uint16_t voltage_raw = ((uint16_t)payload[0] << 8) | (uint16_t)payload[1];
        uint16_t current_raw = ((uint16_t)payload[2] << 8) | (uint16_t)payload[3];
        uint32_t capacity = ((uint32_t)payload[4] << 16) | ((uint32_t)payload[5] << 8) | (uint32_t)payload[6];
        uint8_t remaining = payload[7];

        st->crsf_log.voltage_v = (double)voltage_raw / 10.0;
        st->crsf_log.current_raw = (double)current_raw;
        st->crsf_log.capacity_mah = capacity;
        st->crsf_log.remaining_pct = remaining;
        st->crsf_log.has_battery = true;
    } else if (type == 0x02 && payload_len >= 15) {
        int32_t lat_raw = (int32_t)((uint32_t)payload[0] << 24 | (uint32_t)payload[1] << 16 |
                                    (uint32_t)payload[2] << 8 | (uint32_t)payload[3]);
        int32_t lon_raw = (int32_t)((uint32_t)payload[4] << 24 | (uint32_t)payload[5] << 16 |
                                    (uint32_t)payload[6] << 8 | (uint32_t)payload[7]);
        uint16_t groundspeed = ((uint16_t)payload[8] << 8) | (uint16_t)payload[9];
        uint16_t heading = ((uint16_t)payload[10] << 8) | (uint16_t)payload[11];
        uint16_t altitude = ((uint16_t)payload[12] << 8) | (uint16_t)payload[13];
        uint8_t sats = payload[14];

        st->crsf_log.latitude_deg = (double)lat_raw / 1e7;
        st->crsf_log.longitude_deg = (double)lon_raw / 1e7;
        st->crsf_log.groundspeed_raw = (double)groundspeed;
        st->crsf_log.heading_deg = (double)heading / 100.0;
        st->crsf_log.altitude_m = (double)((int)altitude - 1000);
        st->crsf_log.sats = sats;
        st->crsf_log.has_gps = true;
    } else {
        return;
    }

    crsf_log_maybe_write(cfg, &st->crsf_log);
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
    size_t payload_len = (size_t)len_field >= 2 ? (size_t)len_field - 2 : 0;

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

    crsf_log_update(cfg, st, s->frame[2], s->frame + 3, payload_len);

    if (!st->udp_peer_set) {
        st->drops_uart_to_net += (uint64_t)s->len;
        return;
    }

    if (cfg->crsf_coalesce) {
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

    udp_flush_if_ready(cfg, st, false,
        st->udp_out_len >= (size_t)cfg->udp_coalesce_bytes ? "size_threshold" : "pending");
}

/* --------------------------------- main ------------------------------------- */
int main(int argc, char **argv){
    const char *conf_path = DEFAULT_CONF;

    for (int i=1;i<argc;i++){
        if (!strcmp(argv[i],"-c") && i+1<argc) { conf_path=argv[++i]; }
        else if (argv[i][0]=='-' && argv[i][1]=='v') {
            g_verbosity = 1;
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

    crsf_monitor_t crsf;
    crsf_monitor_init(&crsf, cfg.crsf_detect && g_verbosity);

    state_t st; memset(&st,0,sizeof(st));
    st.fd_uart=st.fd_net=-1; st.fd_stdout=-1;
    st.epfd=epoll_create1(0); if(st.epfd<0){ perror("epoll_create1"); return 1; }

    crsf_log_apply_config(&st.crsf_log, &cfg);

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

                crsf_monitor_set_enabled(&crsf, cfg.crsf_detect && g_verbosity);
                crsf_log_apply_config(&st.crsf_log, &cfg);

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
                    bool crsf_mode = cfg.crsf_detect != 0;

                    get_mono(&st.last_uart_rx);
                    if (crsf.enabled) {
                        crsf_monitor_feed(&crsf, CRSF_FROM_UART, buf_uart, (size_t)r);
                    }

                    if (crsf_mode) {
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
                    if (crsf.enabled) {
                        crsf_monitor_feed(&crsf, CRSF_FROM_UDP, buf_net, (size_t)r);
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
        crsf_monitor_maybe_report(&crsf);
    }

    maybe_print_stats(&st);
    crsf_monitor_maybe_report(&crsf);
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
