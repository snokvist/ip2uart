// retrans_sender.c
// Poll nl80211 station stats and emit a retransmission score (raw + smoothed).
//
// Build: gcc -O2 -Wall -Wextra retrans_sender.c -o retrans_sender
// Run : ./retrans_sender --watch 0.1 --debugfs
//        /sys/kernel/debug/ieee80211/phy0/netdev:waybeam0/stations/98:03:cf:cf:a4:28
//        waybeam0 98:03:cf:cf:a4:28
//
// Notes:
// - Requires linux uapi headers: linux/netlink.h, linux/genetlink.h, linux/nl80211.h
// - Must run as root (or have CAP_NET_ADMIN / CAP_NET_RAW), depending on distro policy.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef NLMSG_ALIGNTO
#define NLMSG_ALIGNTO 4
#endif
#ifndef NLMSG_ALIGN
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#endif

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif

struct nlattr_min {
    uint16_t nla_len;
    uint16_t nla_type;
};

#define NLA_DATA(na) ((void *)((char *)(na) + NLA_HDRLEN))
#define NLA_LEN(na)  ((int)((na)->nla_len) - NLA_HDRLEN)

static inline bool nla_ok(const struct nlattr_min *nla, int rem) {
    return rem >= (int)sizeof(*nla) && nla->nla_len >= sizeof(*nla) &&
           nla->nla_len <= rem;
}
static inline struct nlattr_min *nla_next(struct nlattr_min *nla, int *rem) {
    int totlen = NLA_ALIGN(nla->nla_len);
    *rem -= totlen;
    return (struct nlattr_min *)((char *)nla + totlen);
}

static uint32_t g_seq = 0;

struct station_info_data {
    bool have_mac;
    uint8_t mac[6];
    char mac_string[18];

    uint32_t rx_pkts;
    uint32_t tx_pkts;
    uint32_t tx_retries;
    uint32_t tx_failed;
    uint64_t rx_drop_misc;
    uint64_t fcs_error_count;

    uint64_t rx_duplicates;
    bool have_rx_duplicates;
};

struct link_score {
    double score;
    double smoothed_score;
    double retry_ratio;
    double fail_ratio;
    double drop_ratio;
    double remote_retry_ratio;
    double sample_confidence;
    uint64_t delta_rx_pkts;
    uint64_t delta_tx_pkts;
    uint64_t delta_tx_retries;
    uint64_t delta_tx_failed;
    uint64_t delta_rx_drop_misc;
    uint64_t delta_fcs_error_count;
    uint64_t delta_rx_duplicates;
};

typedef void (*station_info_handler)(const struct station_info_data *, void *);

static double clamp01(double v) {
    if (v < 0.0) return 0.0;
    if (v > 1.0) return 1.0;
    return v;
}

static uint64_t delta_counter(uint64_t current, uint64_t previous) {
    return (current >= previous) ? (current - previous) : current;
}

static int nl_send(int fd, const void *buf, size_t len) {
    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
    struct msghdr msg = { .msg_name = &nladdr, .msg_namelen = sizeof(nladdr),
                          .msg_iov = &iov, .msg_iovlen = 1 };
    return (int)sendmsg(fd, &msg, 0);
}

static int nl_recv(int fd, void *buf, size_t len) {
    struct sockaddr_nl nladdr = {0};
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    struct msghdr msg = { .msg_name = &nladdr, .msg_namelen = sizeof(nladdr),
                          .msg_iov = &iov, .msg_iovlen = 1 };
    return (int)recvmsg(fd, &msg, 0);
}

static int nla_put(void *msgbuf, size_t msgbuf_sz, size_t *off, uint16_t type,
                   const void *data, uint16_t datalen) {
    size_t needed = NLA_ALIGN(NLA_HDRLEN + datalen);
    if (*off + needed > msgbuf_sz) return -ENOBUFS;

    struct nlattr_min *na = (struct nlattr_min *)((char *)msgbuf + *off);
    na->nla_type = type;
    na->nla_len  = (uint16_t)(NLA_HDRLEN + datalen);
    if (datalen) memcpy(NLA_DATA(na), data, datalen);

    size_t pad = needed - (NLA_HDRLEN + datalen);
    if (pad) memset((char *)NLA_DATA(na) + datalen, 0, pad);

    *off += needed;
    return 0;
}

static int nla_put_u32(void *msgbuf, size_t msgbuf_sz, size_t *off,
                       uint16_t type, uint32_t v) {
    return nla_put(msgbuf, msgbuf_sz, off, type, &v, sizeof(v));
}

static int nla_put_string(void *msgbuf, size_t msgbuf_sz, size_t *off,
                          uint16_t type, const char *s) {
    return nla_put(msgbuf, msgbuf_sz, off, type, s,
                   (uint16_t)(strlen(s) + 1));
}

static bool parse_mac(const char *s, uint8_t mac[6]) {
    unsigned int b[6];
    if (sscanf(s, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return false;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)b[i];
    return true;
}

static void mac_to_str(const uint8_t mac[6], char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int genl_resolve_family(int fd, const char *family_name) {
    char buf[4096];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *gh = (struct genlmsghdr *)(buf + NLMSG_HDRLEN);

    nlh->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN;
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++g_seq;
    nlh->nlmsg_pid = (uint32_t)getpid();

    gh->cmd = CTRL_CMD_GETFAMILY;
    gh->version = 1;

    size_t off = NLMSG_HDRLEN + GENL_HDRLEN;
    if (nla_put_string(buf, sizeof(buf), &off, CTRL_ATTR_FAMILY_NAME,
                       family_name) != 0) {
        return -ENOBUFS;
    }
    nlh->nlmsg_len = (uint32_t)off;

    if (nl_send(fd, buf, nlh->nlmsg_len) < 0) return -errno;

    int r = nl_recv(fd, buf, sizeof(buf));
    if (r < 0) return -errno;

    for (struct nlmsghdr *h = (struct nlmsghdr *)buf;
         NLMSG_OK(h, (unsigned int)r); h = NLMSG_NEXT(h, r)) {
        if (h->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);
            return e->error ? e->error : -EIO;
        }
        if (h->nlmsg_type != GENL_ID_CTRL) continue;

        struct genlmsghdr *g = (struct genlmsghdr *)NLMSG_DATA(h);
        int rem = (int)(h->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN);
        struct nlattr_min *na = (struct nlattr_min *)((char *)g + GENL_HDRLEN);

        for (; nla_ok(na, rem); na = nla_next(na, &rem)) {
            if (na->nla_type == CTRL_ATTR_FAMILY_ID && NLA_LEN(na) >= 2) {
                uint16_t id;
                memcpy(&id, NLA_DATA(na), sizeof(id));
                return (int)id;
            }
        }
    }
    return -ENOENT;
}

static uint32_t get_u32(const struct nlattr_min *na) {
    uint32_t v = 0;
    if (NLA_LEN(na) >= 4) memcpy(&v, NLA_DATA(na), 4);
    return v;
}
static uint64_t get_u64(const struct nlattr_min *na) {
    uint64_t v = 0;
    if (NLA_LEN(na) >= 8) memcpy(&v, NLA_DATA(na), 8);
    return v;
}
static void parse_station_msg(const struct nlmsghdr *h,
                              station_info_handler handler, void *ctx) {
    const struct genlmsghdr *g = (const struct genlmsghdr *)NLMSG_DATA(h);
    int rem = (int)(h->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN);
    struct nlattr_min *na = (struct nlattr_min *)((char *)g + GENL_HDRLEN);

    struct station_info_data info = {0};
    const struct nlattr_min *sta_info = NULL;

    for (; nla_ok(na, rem); na = nla_next(na, &rem)) {
        switch (na->nla_type) {
            case NL80211_ATTR_MAC:
                if (NLA_LEN(na) >= 6) {
                    memcpy(info.mac, NLA_DATA(na), 6);
                    info.have_mac = true;
                }
                break;
            case NL80211_ATTR_STA_INFO:
                sta_info = na;
                break;
            default:
                break;
        }
    }

    if (sta_info) {
        int r2 = NLA_LEN(sta_info);
        struct nlattr_min *si = (struct nlattr_min *)NLA_DATA(sta_info);
        for (; nla_ok(si, r2); si = nla_next(si, &r2)) {
            switch (si->nla_type) {
                case NL80211_STA_INFO_RX_PACKETS:
                    info.rx_pkts = get_u32(si);
                    break;
                case NL80211_STA_INFO_TX_PACKETS:
                    info.tx_pkts = get_u32(si);
                    break;
                case NL80211_STA_INFO_TX_RETRIES:
                    info.tx_retries = get_u32(si);
                    break;
                case NL80211_STA_INFO_TX_FAILED:
                    info.tx_failed = get_u32(si);
                    break;
                case NL80211_STA_INFO_RX_DROP_MISC:
                    info.rx_drop_misc = get_u64(si);
                    break;
                case NL80211_STA_INFO_FCS_ERROR_COUNT:
                    info.fcs_error_count = get_u64(si);
                    break;
                default:
                    break;
            }
        }
    }

    strcpy(info.mac_string, "00:00:00:00:00:00");
    if (info.have_mac) mac_to_str(info.mac, info.mac_string);

    if (handler) handler(&info, ctx);
}

static void compute_link_score(const struct station_info_data *prev,
                               const struct station_info_data *cur,
                               struct link_score *out) {
    memset(out, 0, sizeof(*out));
    out->delta_rx_pkts = delta_counter(cur->rx_pkts, prev->rx_pkts);
    out->delta_tx_pkts = delta_counter(cur->tx_pkts, prev->tx_pkts);
    out->delta_tx_retries = delta_counter(cur->tx_retries, prev->tx_retries);
    out->delta_tx_failed = delta_counter(cur->tx_failed, prev->tx_failed);
    out->delta_rx_drop_misc =
        delta_counter(cur->rx_drop_misc, prev->rx_drop_misc);
    out->delta_fcs_error_count =
        delta_counter(cur->fcs_error_count, prev->fcs_error_count);
    out->delta_rx_duplicates =
        delta_counter(cur->rx_duplicates, prev->rx_duplicates);

    uint64_t tx_denominator = out->delta_tx_pkts + out->delta_tx_retries;
    uint64_t tx_fail_denominator = out->delta_tx_pkts + out->delta_tx_failed;
    uint64_t rx_denominator = out->delta_rx_pkts + out->delta_rx_drop_misc +
                              out->delta_fcs_error_count;
    uint64_t total_packets = out->delta_tx_pkts + out->delta_rx_pkts;
    uint64_t remote_retry_denominator =
        out->delta_rx_pkts + out->delta_rx_duplicates;

    out->retry_ratio = tx_denominator ?
        ((double)out->delta_tx_retries / (double)tx_denominator) : 0.0;
    out->fail_ratio = tx_fail_denominator ?
        ((double)out->delta_tx_failed / (double)tx_fail_denominator) : 0.0;
    out->drop_ratio = rx_denominator ?
        ((double)(out->delta_rx_drop_misc + out->delta_fcs_error_count) /
         (double)rx_denominator) : 0.0;
    out->remote_retry_ratio = remote_retry_denominator ?
        ((double)out->delta_rx_duplicates / (double)remote_retry_denominator) :
        0.0;

    out->sample_confidence = clamp01((double)total_packets / 100.0);

    if (total_packets == 0) {
        if (out->delta_tx_retries || out->delta_tx_failed ||
            out->delta_rx_drop_misc || out->delta_fcs_error_count ||
            out->delta_rx_duplicates) {
            out->score = 0.0;
        } else {
            out->score = 100.0;
        }
        out->smoothed_score = out->score;
        return;
    }

    double weighted_error = (out->retry_ratio * 0.5) +
                            (out->fail_ratio * 3.0) +
                            (out->drop_ratio * 1.5) +
                            (out->remote_retry_ratio * 1.0);
    double penalty = clamp01(weighted_error * 2.0 * out->sample_confidence);
    out->score = (1.0 - penalty) * 100.0;
    out->smoothed_score = out->score;
}

static bool read_u64_from_file(const char *path, uint64_t *out) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char buf[64] = {0};
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return false;
    }
    fclose(f);
    char *end = NULL;
    errno = 0;
    uint64_t v = strtoull(buf, &end, 10);
    if (errno != 0 || end == buf) return false;
    *out = v;
    return true;
}

static void read_debugfs_stats(const char *dir, struct station_info_data *info) {
    if (!dir || !info) return;

    char path[PATH_MAX];
    uint64_t v = 0;

    int n = snprintf(path, sizeof(path), "%s/rx_duplicates", dir);
    if (n > 0 && n < (int)sizeof(path) && read_u64_from_file(path, &v)) {
        info->rx_duplicates = v;
        info->have_rx_duplicates = true;
    }
}

struct capture_ctx {
    struct station_info_data info;
    bool seen;
};

static void capture_handler(const struct station_info_data *info, void *ctx) {
    struct capture_ctx *c = (struct capture_ctx *)ctx;
    c->info = *info;
    c->seen = true;
}

static int nl80211_get_station(int fd, int nl80211_id, int ifindex,
                               const uint8_t *mac_opt,
                               station_info_handler handler, void *ctx);

static int capture_station(int fd, int nl80211_id, int ifindex,
                           const uint8_t *mac_opt, const char *debugfs_dir,
                           struct capture_ctx *out_ctx) {
    memset(out_ctx, 0, sizeof(*out_ctx));
    int r = nl80211_get_station(fd, nl80211_id, ifindex, mac_opt,
                                capture_handler, out_ctx);
    if (r < 0) return r;
    if (!out_ctx->seen) return -ENOENT;
    if (debugfs_dir) {
        read_debugfs_stats(debugfs_dir, &out_ctx->info);
    }
    return 0;
}

static int nl80211_get_station(int fd, int nl80211_id, int ifindex,
                               const uint8_t *mac_opt,
                               station_info_handler handler, void *ctx) {
    char buf[8192];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *gh = (struct genlmsghdr *)(buf + NLMSG_HDRLEN);

    nlh->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN;
    nlh->nlmsg_type = (uint16_t)nl80211_id;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    if (!mac_opt) nlh->nlmsg_flags |= NLM_F_DUMP;
    nlh->nlmsg_seq = ++g_seq;
    nlh->nlmsg_pid = (uint32_t)getpid();

    gh->cmd = NL80211_CMD_GET_STATION;
    gh->version = 1;

    size_t off = NLMSG_HDRLEN + GENL_HDRLEN;
    int rc = nla_put_u32(buf, sizeof(buf), &off, NL80211_ATTR_IFINDEX,
                         (uint32_t)ifindex);
    if (rc) return rc;

    if (mac_opt) {
        rc = nla_put(buf, sizeof(buf), &off, NL80211_ATTR_MAC, mac_opt, 6);
        if (rc) return rc;
    }

    nlh->nlmsg_len = (uint32_t)off;

    if (nl_send(fd, buf, nlh->nlmsg_len) < 0) return -errno;

    for (;;) {
        int r = nl_recv(fd, buf, sizeof(buf));
        if (r < 0) return -errno;

        for (struct nlmsghdr *h = (struct nlmsghdr *)buf;
             NLMSG_OK(h, (unsigned int)r); h = NLMSG_NEXT(h, r)) {
            if (h->nlmsg_type == NLMSG_DONE) return 0;
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);
                return e->error ? e->error : -EIO;
            }
            if ((int)h->nlmsg_type != nl80211_id) continue;
            parse_station_msg(h, handler, ctx);
        }

        if (mac_opt) return 0;
    }
}

static void sleep_interval(double seconds) {
    if (seconds <= 0.0) return;
    struct timespec ts;
    ts.tv_sec = (time_t)seconds;
    ts.tv_nsec = (long)((seconds - (double)ts.tv_sec) * 1e9);
    nanosleep(&ts, NULL);
}

static void print_score_json(const char *mac, const struct link_score *score) {
    printf("{\"mac\":\"%s\",\"score\":%.1f,\"smoothed\":%.1f,"
           "\"retry_ratio\":%.4f,\"fail_ratio\":%.4f,\"drop_ratio\":%.4f,"
           "\"remote_retry_ratio\":%.4f,\"sample_confidence\":%.2f,"
           "\"delta_tx_packets\":%" PRIu64 ",\"delta_rx_packets\":%" PRIu64 ","
           "\"delta_tx_retries\":%" PRIu64 ",\"delta_tx_failed\":%" PRIu64 ","
           "\"delta_rx_drop_misc\":%" PRIu64 ","
           "\"delta_fcs_error_count\":%" PRIu64 ","
           "\"delta_rx_duplicates\":%" PRIu64 "}\n",
           mac, score->score, score->smoothed_score, score->retry_ratio,
           score->fail_ratio, score->drop_ratio, score->remote_retry_ratio,
           score->sample_confidence, score->delta_tx_pkts, score->delta_rx_pkts,
           score->delta_tx_retries, score->delta_tx_failed,
           score->delta_rx_drop_misc, score->delta_fcs_error_count,
           score->delta_rx_duplicates);
}

static void print_score_text(const char *mac, const struct link_score *score) {
    printf("%s score=%.1f avg3=%.1f retry=%.4f fail=%.4f drop=%.4f "
           "remote_retry=%.4f conf=%.2f tx=%" PRIu64 " rx=%" PRIu64 "\n",
           mac, score->score, score->smoothed_score, score->retry_ratio,
           score->fail_ratio, score->drop_ratio, score->remote_retry_ratio,
           score->sample_confidence, score->delta_tx_pkts, score->delta_rx_pkts);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [--watch <seconds>] [--json] [--debugfs <dir>] "
                        "<ifname> [peer-mac]\n", argv[0]);
        return 2;
    }

    double watch_interval = 0.0;
    bool watch_mode = false;
    bool json_output = false;
    const char *debugfs_dir = NULL;
    int argi = 1;
    while (argi < argc && strncmp(argv[argi], "--", 2) == 0) {
        if (strncmp(argv[argi], "--watch", 7) == 0) {
            const char *val = NULL;
            if (argv[argi][7] == '=') {
                val = argv[argi] + 8;
            } else if (argi + 1 < argc) {
                val = argv[++argi];
            }
            if (!val) {
                fprintf(stderr, "--watch requires a numeric interval (seconds)\n");
                return 2;
            }
            watch_interval = strtod(val, NULL);
            if (watch_interval <= 0.0) {
                fprintf(stderr, "Invalid watch interval: %s\n", val);
                return 2;
            }
            watch_mode = true;
        } else if (strcmp(argv[argi], "--json") == 0) {
            json_output = true;
        } else if (strcmp(argv[argi], "--debugfs") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "--debugfs requires a directory path\n");
                return 2;
            }
            debugfs_dir = argv[++argi];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[argi]);
            return 2;
        }
        argi++;
    }

    if (argc - argi < 1) {
        fprintf(stderr, "Usage: %s [--watch <seconds>] [--json] [--debugfs <dir>] "
                        "<ifname> [peer-mac]\n", argv[0]);
        return 2;
    }

    const char *ifname = argv[argi++];
    int ifindex = if_nametoindex(ifname);
    if (ifindex <= 0) {
        fprintf(stderr, "if_nametoindex(%s) failed: %s\n", ifname, strerror(errno));
        return 1;
    }

    uint8_t mac[6];
    uint8_t *macp = NULL;
    if (argi < argc) {
        if (!parse_mac(argv[argi], mac)) {
            fprintf(stderr, "Invalid MAC: %s\n", argv[argi]);
            return 2;
        }
        macp = mac;
    }

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0) {
        fprintf(stderr, "netlink socket: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_nl local = {0};
    local.nl_family = AF_NETLINK;
    local.nl_pid = (uint32_t)getpid();
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        fprintf(stderr, "netlink bind: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    int nl80211_id = genl_resolve_family(fd, "nl80211");
    if (nl80211_id < 0) {
        fprintf(stderr, "resolve nl80211 failed: %s\n",
                strerror(-nl80211_id));
        close(fd);
        return 1;
    }

    int rc = 0;
    double window[3] = {0.0, 0.0, 0.0};
    int wcount = 0;
    int wpos = 0;
    double wsum = 0.0;

    struct capture_ctx prev = {0};
    struct capture_ctx cur = {0};

    rc = capture_station(fd, nl80211_id, ifindex, macp, debugfs_dir, &prev);
    if (rc < 0) {
        fprintf(stderr, "GET_STATION failed: %s\n", strerror(-rc));
        close(fd);
        return 1;
    }

    if (watch_mode) {
        while (true) {
            sleep_interval(watch_interval);
            rc = capture_station(fd, nl80211_id, ifindex, macp, debugfs_dir,
                                 &cur);
            if (rc < 0) {
                fprintf(stderr, "GET_STATION failed: %s\n", strerror(-rc));
                break;
            }

            struct link_score score;
            compute_link_score(&prev.info, &cur.info, &score);
            double raw = score.score;
            if (wcount < 3) {
                window[wcount++] = raw;
                wsum += raw;
            } else {
                wsum -= window[wpos];
                window[wpos] = raw;
                wsum += raw;
                wpos = (wpos + 1) % 3;
            }
            score.smoothed_score = wsum / (double)wcount;

            if (json_output) print_score_json(cur.info.mac_string, &score);
            else             print_score_text(cur.info.mac_string, &score);

            prev = cur;
        }
    } else {
        const double sample_delay = 0.1;
        sleep_interval(sample_delay);
        rc = capture_station(fd, nl80211_id, ifindex, macp, debugfs_dir, &cur);
        if (rc < 0) {
            fprintf(stderr, "GET_STATION failed: %s\n", strerror(-rc));
            close(fd);
            return 1;
        }
        struct link_score score;
        compute_link_score(&prev.info, &cur.info, &score);
        window[wcount++] = score.score;
        wsum = score.score;
        score.smoothed_score = score.score;
        if (json_output) print_score_json(cur.info.mac_string, &score);
        else             print_score_text(cur.info.mac_string, &score);
    }

    close(fd);
    return rc ? 1 : 0;
}
