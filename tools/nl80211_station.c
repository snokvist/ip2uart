// nl80211_station.c
// Pure netlink (no libnl): query nl80211 station info like "iw dev <if> station dump"
//
// Build: gcc -O2 -Wall -Wextra nl80211_station.c -o nl80211_station
// Run : ./nl80211_station waybeam0 98:03:cf:cf:a4:28
//   or ./nl80211_station waybeam0 (dump all, prints each station)
//
// Notes:
// - Requires linux uapi headers: linux/netlink.h, linux/genetlink.h, linux/nl80211.h
// - Must run as root (or have CAP_NET_ADMIN / CAP_NET_RAW), depending on distro policy.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <inttypes.h>
#include <limits.h>
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
    return rem >= (int)sizeof(*nla) && nla->nla_len >= sizeof(*nla) && nla->nla_len <= rem;
}
static inline struct nlattr_min *nla_next(struct nlattr_min *nla, int *rem) {
    int totlen = NLA_ALIGN(nla->nla_len);
    *rem -= totlen;
    return (struct nlattr_min *)((char *)nla + totlen);
}

static uint32_t g_seq = 0;

struct rate_info {
    bool present;
    bool have_bitrate;
    uint32_t bitrate100kbps;
    int mcs;
    int width_mhz;
    bool sgi;
};

#define MAX_CHAINS 16
struct chain_signal_info {
    bool present;
    int count;
    int8_t values[MAX_CHAINS];
};

struct station_info_data {
    bool have_mac;
    uint8_t mac[6];
    char mac_string[18];

    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint32_t rx_pkts;
    uint32_t tx_pkts;
    uint32_t tx_retries;
    uint32_t tx_failed;
    uint64_t rx_drop_misc;
    uint64_t fcs_error_count;
    uint64_t rx_mpdus;
    uint64_t rx_duration;
    uint64_t tx_duration;
    bool have_rx_drop_misc;
    bool have_fcs_error_count;
    bool have_rx_mpdus;
    bool have_rx_duration;
    bool have_tx_duration;
    uint64_t rx_duplicates;
    uint64_t rx_fragments;
    uint64_t tx_filtered;
    bool have_rx_duplicates;
    bool have_rx_fragments;
    bool have_tx_filtered;

    bool have_signal;
    bool have_signal_avg;
    int8_t signal;
    int8_t signal_avg;

    struct rate_info tx_rate;
    struct rate_info rx_rate;
    struct chain_signal_info chain_sig;
    struct chain_signal_info chain_sig_avg;

    uint32_t expected_throughput;
    bool have_expected_throughput;
};

struct link_score {
    double score;
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
    uint64_t delta_rx_fragments;
    uint64_t delta_tx_filtered;
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

    n = snprintf(path, sizeof(path), "%s/rx_fragments", dir);
    if (n > 0 && n < (int)sizeof(path) && read_u64_from_file(path, &v)) {
        info->rx_fragments = v;
        info->have_rx_fragments = true;
    }

    n = snprintf(path, sizeof(path), "%s/tx_filtered", dir);
    if (n > 0 && n < (int)sizeof(path) && read_u64_from_file(path, &v)) {
        info->tx_filtered = v;
        info->have_tx_filtered = true;
    }
}

static int nl_send(int fd, const void *buf, size_t len) {
    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
    struct msghdr msg = { .msg_name = &nladdr, .msg_namelen = sizeof(nladdr), .msg_iov = &iov, .msg_iovlen = 1 };
    return (int)sendmsg(fd, &msg, 0);
}

static int nl_recv(int fd, void *buf, size_t len) {
    struct sockaddr_nl nladdr = {0};
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    struct msghdr msg = { .msg_name = &nladdr, .msg_namelen = sizeof(nladdr), .msg_iov = &iov, .msg_iovlen = 1 };
    return (int)recvmsg(fd, &msg, 0);
}

static int nla_put(void *msgbuf, size_t msgbuf_sz, size_t *off, uint16_t type, const void *data, uint16_t datalen) {
    size_t needed = NLA_ALIGN(NLA_HDRLEN + datalen);
    if (*off + needed > msgbuf_sz) return -ENOBUFS;

    struct nlattr_min *na = (struct nlattr_min *)((char *)msgbuf + *off);
    na->nla_type = type;
    na->nla_len  = (uint16_t)(NLA_HDRLEN + datalen);
    if (datalen) memcpy(NLA_DATA(na), data, datalen);

    // pad
    size_t pad = needed - (NLA_HDRLEN + datalen);
    if (pad) memset((char *)NLA_DATA(na) + datalen, 0, pad);

    *off += needed;
    return 0;
}

static int nla_put_u32(void *msgbuf, size_t msgbuf_sz, size_t *off, uint16_t type, uint32_t v) {
    return nla_put(msgbuf, msgbuf_sz, off, type, &v, sizeof(v));
}
static int nla_put_string(void *msgbuf, size_t msgbuf_sz, size_t *off, uint16_t type, const char *s) {
    return nla_put(msgbuf, msgbuf_sz, off, type, s, (uint16_t)(strlen(s) + 1));
}

static bool parse_mac(const char *s, uint8_t mac[6]) {
    unsigned int b[6];
    if (sscanf(s, "%02x:%02x:%02x:%02x:%02x:%02x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return false;
    for (int i=0;i<6;i++) mac[i] = (uint8_t)b[i];
    return true;
}

static void mac_to_str(const uint8_t mac[6], char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Resolve generic-netlink family id for "nl80211"
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
    if (nla_put_string(buf, sizeof(buf), &off, CTRL_ATTR_FAMILY_NAME, family_name) != 0) {
        return -ENOBUFS;
    }
    nlh->nlmsg_len = (uint32_t)off;

    if (nl_send(fd, buf, nlh->nlmsg_len) < 0) return -errno;

    int r = nl_recv(fd, buf, sizeof(buf));
    if (r < 0) return -errno;

    for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned int)r); h = NLMSG_NEXT(h, r)) {
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
static uint16_t get_u16_attr(const struct nlattr_min *na) {
    uint16_t v = 0;
    if (NLA_LEN(na) >= 2) memcpy(&v, NLA_DATA(na), 2);
    return v;
}
static uint64_t get_u64(const struct nlattr_min *na) {
    uint64_t v = 0;
    if (NLA_LEN(na) >= 8) memcpy(&v, NLA_DATA(na), 8);
    return v;
}
static int8_t get_s8(const struct nlattr_min *na) {
    int8_t v = 0;
    if (NLA_LEN(na) >= 1) memcpy(&v, NLA_DATA(na), 1);
    return v;
}

static void fill_rate_info(const struct nlattr_min *rateinfo, struct rate_info *out) {
    memset(out, 0, sizeof(*out));
    out->mcs = -1;
    out->width_mhz = -1;
    out->present = true;

    int rem = NLA_LEN(rateinfo);
    struct nlattr_min *na = (struct nlattr_min *)NLA_DATA(rateinfo);

    for (; nla_ok(na, rem); na = nla_next(na, &rem)) {
        switch (na->nla_type) {
            case NL80211_RATE_INFO_BITRATE:
                // usually u16 in units of 100 kbit/s
                if (NLA_LEN(na) >= 2) {
                    out->bitrate100kbps = (uint32_t)get_u16_attr(na);
                    out->have_bitrate = true;
                }
                break;
            case NL80211_RATE_INFO_BITRATE32:
                out->bitrate100kbps = get_u32(na);
                out->have_bitrate = true;
                break;
            case NL80211_RATE_INFO_MCS:
                out->mcs = *(uint8_t *)NLA_DATA(na);
                break;
            case NL80211_RATE_INFO_40_MHZ_WIDTH:
                out->width_mhz = 40;
                break;
            case NL80211_RATE_INFO_80_MHZ_WIDTH:
                out->width_mhz = 80;
                break;
            case NL80211_RATE_INFO_80P80_MHZ_WIDTH:
                out->width_mhz = 160; // represent as 160-ish
                break;
            case NL80211_RATE_INFO_160_MHZ_WIDTH:
                out->width_mhz = 160;
                break;
            case NL80211_RATE_INFO_SHORT_GI:
                out->sgi = true;
                break;
            default:
                break;
        }
    }
}

static void print_rate_info(const struct rate_info *ri, const char *label) {
    printf("  \"%s\": {", label);
    if (ri && ri->have_bitrate) {
        double mbps = ri->bitrate100kbps / 10.0;
        printf("\"mbps\": %.1f", mbps);
    } else {
        printf("\"mbps\": null");
    }

    if (ri && ri->mcs >= 0) printf(", \"mcs\": %d", ri->mcs);
    else                    printf(", \"mcs\": null");

    if (ri && ri->width_mhz > 0) printf(", \"width_mhz\": %d", ri->width_mhz);
    else                         printf(", \"width_mhz\": null");

    printf(", \"sgi\": %s", (ri && ri->sgi) ? "true" : "false");
    printf("}");
}

static void fill_chain_signal(const struct nlattr_min *chain_attr, struct chain_signal_info *out) {
    memset(out, 0, sizeof(*out));
    out->present = true;

    int rem = NLA_LEN(chain_attr);
    struct nlattr_min *na = (struct nlattr_min *)NLA_DATA(chain_attr);
    for (; nla_ok(na, rem) && out->count < MAX_CHAINS; na = nla_next(na, &rem)) {
        out->values[out->count++] = get_s8(na);
    }
}

static void print_chain_signal(const struct chain_signal_info *ci, const char *label) {
    printf("  \"%s\": [", label);
    if (ci && ci->present) {
        for (int i = 0; i < ci->count; i++) {
            if (i > 0) printf(", ");
            printf("%d", (int)ci->values[i]);
        }
    }
    printf("]");
}

static void parse_station_msg(const struct nlmsghdr *h, station_info_handler handler, void *ctx) {
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
                case NL80211_STA_INFO_RX_BYTES64: info.rx_bytes = get_u64(si); break;
                case NL80211_STA_INFO_TX_BYTES64: info.tx_bytes = get_u64(si); break;
                case NL80211_STA_INFO_RX_BYTES:   info.rx_bytes = get_u32(si); break;
                case NL80211_STA_INFO_TX_BYTES:   info.tx_bytes = get_u32(si); break;
                case NL80211_STA_INFO_RX_PACKETS: info.rx_pkts = get_u32(si); break;
                case NL80211_STA_INFO_TX_PACKETS: info.tx_pkts = get_u32(si); break;
                case NL80211_STA_INFO_TX_RETRIES: info.tx_retries = get_u32(si); break;
                case NL80211_STA_INFO_TX_FAILED:  info.tx_failed = get_u32(si); break;
                case NL80211_STA_INFO_RX_DROP_MISC:
                    info.rx_drop_misc = get_u64(si);
                    info.have_rx_drop_misc = true;
                    break;
                case NL80211_STA_INFO_FCS_ERROR_COUNT:
                    info.fcs_error_count = get_u64(si);
                    info.have_fcs_error_count = true;
                    break;
                case NL80211_STA_INFO_RX_MPDUS:
                    info.rx_mpdus = get_u64(si);
                    info.have_rx_mpdus = true;
                    break;
                case NL80211_STA_INFO_RX_DURATION:
                    info.rx_duration = get_u64(si);
                    info.have_rx_duration = true;
                    break;
                case NL80211_STA_INFO_TX_DURATION:
                    info.tx_duration = get_u64(si);
                    info.have_tx_duration = true;
                    break;
                case NL80211_STA_INFO_SIGNAL:
                    info.signal = get_s8(si);
                    info.have_signal = true;
                    break;
                case NL80211_STA_INFO_SIGNAL_AVG:
                    info.signal_avg = get_s8(si);
                    info.have_signal_avg = true;
                    break;
                case NL80211_STA_INFO_TX_BITRATE:
                    fill_rate_info(si, &info.tx_rate);
                    break;
                case NL80211_STA_INFO_RX_BITRATE:
                    fill_rate_info(si, &info.rx_rate);
                    break;
                case NL80211_STA_INFO_CHAIN_SIGNAL:
                    fill_chain_signal(si, &info.chain_sig);
                    break;
                case NL80211_STA_INFO_CHAIN_SIGNAL_AVG:
                    fill_chain_signal(si, &info.chain_sig_avg);
                    break;
                case NL80211_STA_INFO_EXPECTED_THROUGHPUT:
                    info.expected_throughput = get_u32(si);
                    info.have_expected_throughput = true;
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
    out->delta_rx_drop_misc = delta_counter(cur->rx_drop_misc, prev->rx_drop_misc);
    out->delta_fcs_error_count =
        delta_counter(cur->fcs_error_count, prev->fcs_error_count);
    out->delta_rx_duplicates =
        delta_counter(cur->rx_duplicates, prev->rx_duplicates);
    out->delta_rx_fragments =
        delta_counter(cur->rx_fragments, prev->rx_fragments);
    out->delta_tx_filtered =
        delta_counter(cur->tx_filtered, prev->tx_filtered);

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
        return;
    }

    double weighted_error = (out->retry_ratio * 0.5) +
                            (out->fail_ratio * 3.0) +
                            (out->drop_ratio * 1.5) +
                            (out->remote_retry_ratio * 1.0);
    double penalty = clamp01(weighted_error * 2.0 * out->sample_confidence);
    out->score = (1.0 - penalty) * 100.0;
}

static void print_station_info(const struct station_info_data *info,
                               const struct link_score *score) {
    printf("{\n");
    printf("  \"mac\": \"%s\",\n", info->mac_string);
    printf("  \"rx_bytes\": %" PRIu64 ",\n", (uint64_t)info->rx_bytes);
    printf("  \"rx_packets\": %u,\n", info->rx_pkts);
    printf("  \"tx_bytes\": %" PRIu64 ",\n", (uint64_t)info->tx_bytes);
    printf("  \"tx_packets\": %u,\n", info->tx_pkts);
    printf("  \"tx_retries\": %u,\n", info->tx_retries);
    printf("  \"tx_failed\": %u,\n", info->tx_failed);

    if (info->have_rx_drop_misc)
        printf("  \"rx_drop_misc\": %" PRIu64 ",\n", info->rx_drop_misc);
    else
        printf("  \"rx_drop_misc\": null,\n");

    if (info->have_fcs_error_count)
        printf("  \"fcs_error_count\": %" PRIu64 ",\n", info->fcs_error_count);
    else
        printf("  \"fcs_error_count\": null,\n");

    if (info->have_rx_mpdus)
        printf("  \"rx_mpdus\": %" PRIu64 ",\n", info->rx_mpdus);
    else
        printf("  \"rx_mpdus\": null,\n");

    if (info->have_rx_duration)
        printf("  \"rx_duration_usecs\": %" PRIu64 ",\n", info->rx_duration);
    else
        printf("  \"rx_duration_usecs\": null,\n");

    if (info->have_tx_duration)
        printf("  \"tx_duration_usecs\": %" PRIu64 ",\n", info->tx_duration);
    else
        printf("  \"tx_duration_usecs\": null,\n");

    if (info->have_rx_duplicates)
        printf("  \"rx_duplicates\": %" PRIu64 ",\n", info->rx_duplicates);
    else
        printf("  \"rx_duplicates\": null,\n");

    if (info->have_rx_fragments)
        printf("  \"rx_fragments\": %" PRIu64 ",\n", info->rx_fragments);
    else
        printf("  \"rx_fragments\": null,\n");

    if (info->have_tx_filtered)
        printf("  \"tx_filtered\": %" PRIu64 ",\n", info->tx_filtered);
    else
        printf("  \"tx_filtered\": null,\n");

    if (info->have_signal)
        printf("  \"signal_dbm\": %d,\n", (int)info->signal);
    else
        printf("  \"signal_dbm\": null,\n");

    if (info->have_signal_avg)
        printf("  \"signal_avg_dbm\": %d,\n", (int)info->signal_avg);
    else
        printf("  \"signal_avg_dbm\": null,\n");

    if (info->chain_sig.present) {
        print_chain_signal(&info->chain_sig, "chain_signal_dbm");
        printf(",\n");
    } else {
        printf("  \"chain_signal_dbm\": null,\n");
    }

    if (info->chain_sig_avg.present) {
        print_chain_signal(&info->chain_sig_avg, "chain_signal_avg_dbm");
        printf(",\n");
    } else {
        printf("  \"chain_signal_avg_dbm\": null,\n");
    }

    if (info->tx_rate.present) {
        print_rate_info(&info->tx_rate, "tx_rate");
        printf(",\n");
    } else {
        printf("  \"tx_rate\": null,\n");
    }

    if (info->rx_rate.present) {
        print_rate_info(&info->rx_rate, "rx_rate");
        printf(",\n");
    } else {
        printf("  \"rx_rate\": null,\n");
    }

    if (info->have_expected_throughput) {
        printf("  \"expected_throughput_kbps\": %u", info->expected_throughput);
    } else {
        printf("  \"expected_throughput_kbps\": null");
    }

    if (score) {
        printf(",\n");
        printf("  \"link_score\": {\n");
        printf("    \"value\": %.1f,\n", score->score);
        printf("    \"retry_ratio\": %.4f,\n", score->retry_ratio);
        printf("    \"fail_ratio\": %.4f,\n", score->fail_ratio);
        printf("    \"drop_ratio\": %.4f,\n", score->drop_ratio);
        printf("    \"remote_retry_ratio\": %.4f,\n",
               score->remote_retry_ratio);
        printf("    \"sample_confidence\": %.2f,\n", score->sample_confidence);
        printf("    \"delta_tx_packets\": %" PRIu64 ",\n", score->delta_tx_pkts);
        printf("    \"delta_rx_packets\": %" PRIu64 ",\n", score->delta_rx_pkts);
        printf("    \"delta_tx_retries\": %" PRIu64 ",\n",
               score->delta_tx_retries);
        printf("    \"delta_tx_failed\": %" PRIu64 ",\n",
               score->delta_tx_failed);
        printf("    \"delta_rx_drop_misc\": %" PRIu64 ",\n",
               score->delta_rx_drop_misc);
        printf("    \"delta_fcs_error_count\": %" PRIu64 ",\n",
               score->delta_fcs_error_count);
        printf("    \"delta_rx_duplicates\": %" PRIu64 ",\n",
               score->delta_rx_duplicates);
        printf("    \"delta_rx_fragments\": %" PRIu64 ",\n",
               score->delta_rx_fragments);
        printf("    \"delta_tx_filtered\": %" PRIu64 "\n",
               score->delta_tx_filtered);
        printf("  }\n");
    } else {
        printf("\n");
    }
    printf("}\n");
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

static void sleep_interval(double seconds) {
    if (seconds <= 0.0) return;
    struct timespec ts;
    ts.tv_sec = (time_t)seconds;
    ts.tv_nsec = (long)((seconds - (double)ts.tv_sec) * 1e9);
    nanosleep(&ts, NULL);
}

static int nl80211_get_station(int fd,
                               int nl80211_id,
                               int ifindex,
                               const uint8_t *mac_opt /* nullable */,
                               station_info_handler handler,
                               void *ctx) {
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
    int rc = nla_put_u32(buf, sizeof(buf), &off, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    if (rc) return rc;

    if (mac_opt) {
        rc = nla_put(buf, sizeof(buf), &off, NL80211_ATTR_MAC, mac_opt, 6);
        if (rc) return rc;
    }

    nlh->nlmsg_len = (uint32_t)off;

    if (nl_send(fd, buf, nlh->nlmsg_len) < 0) return -errno;

    // Receive multipart reply when dumping.
    for (;;) {
        int r = nl_recv(fd, buf, sizeof(buf));
        if (r < 0) return -errno;

        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned int)r); h = NLMSG_NEXT(h, r)) {
            if (h->nlmsg_type == NLMSG_DONE) return 0;
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);
                return e->error ? e->error : -EIO;
            }
            // Filter to our nl80211 replies (family id)
            if ((int)h->nlmsg_type != nl80211_id) continue;
            parse_station_msg(h, handler, ctx);
        }

        if (mac_opt) {
            // Single query: usually one reply, no NLMSG_DONE
            return 0;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [--watch <seconds>] [--json] [--debugfs <dir>] <ifname> [peer-mac]\n", argv[0]);
        return 2;
    }

    double watch_interval = 0.0;
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
        fprintf(stderr, "Usage: %s [--watch <seconds>] [--json] [--debugfs <dir>] <ifname> [peer-mac]\n", argv[0]);
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
        fprintf(stderr, "resolve nl80211 failed: %s\n", strerror(-nl80211_id));
        close(fd);
        return 1;
    }
    int rc = 0;

    if (watch_interval > 0.0) {
        struct capture_ctx ctx = {0};
        struct station_info_data prev = {0};
        bool have_prev = false;

        while (true) {
            memset(&ctx, 0, sizeof(ctx));
            rc = nl80211_get_station(fd, nl80211_id, ifindex, macp, capture_handler, &ctx);
            if (rc < 0) {
                fprintf(stderr, "GET_STATION failed: %s\n", strerror(-rc));
                break;
            }
            if (!ctx.seen) {
                fprintf(stderr, "No station data received\n");
                rc = -ENOENT;
                break;
            }

            if (debugfs_dir) {
                read_debugfs_stats(debugfs_dir, &ctx.info);
            }

            struct link_score score;
            struct link_score *scorep = NULL;
            if (have_prev) {
                compute_link_score(&prev, &ctx.info, &score);
                scorep = &score;
            }

            if (json_output) {
                print_station_info(&ctx.info, scorep);
            } else {
                if (scorep) {
                    printf("score=%.1f retry=%.4f fail=%.4f drop=%.4f remote_retry=%.4f conf=%.2f "
                           "tx=%" PRIu64 " rx=%" PRIu64 "\n",
                           scorep->score, scorep->retry_ratio, scorep->fail_ratio,
                           scorep->drop_ratio, scorep->remote_retry_ratio,
                           scorep->sample_confidence, scorep->delta_tx_pkts,
                           scorep->delta_rx_pkts);
                } else {
                    printf("score=-- (priming)\n");
                }
            }
            fflush(stdout);

            prev = ctx.info;
            have_prev = true;
            sleep_interval(watch_interval);
        }
    } else {
        struct capture_ctx ctx = {0};
        rc = nl80211_get_station(fd, nl80211_id, ifindex, macp, capture_handler, &ctx);
        if (rc < 0) {
            fprintf(stderr, "GET_STATION failed: %s\n", strerror(-rc));
            close(fd);
            return 1;
        }
        if (!ctx.seen) {
            fprintf(stderr, "No station data received\n");
            close(fd);
            return 1;
        }
        if (debugfs_dir) {
            read_debugfs_stats(debugfs_dir, &ctx.info);
        }
        print_station_info(&ctx.info, NULL);
    }

    close(fd);
    return rc ? 1 : 0;
}
