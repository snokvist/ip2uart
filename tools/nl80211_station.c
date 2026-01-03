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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
static int nla_put_u16(void *msgbuf, size_t msgbuf_sz, size_t *off, uint16_t type, uint16_t v) {
    return nla_put(msgbuf, msgbuf_sz, off, type, &v, sizeof(v));
}
static int nla_put_u8(void *msgbuf, size_t msgbuf_sz, size_t *off, uint16_t type, uint8_t v) {
    return nla_put(msgbuf, msgbuf_sz, off, type, &v, sizeof(v));
}
static int nla_put_string(void *msgbuf, size_t msgbuf_sz, size_t *off, uint16_t type, const char *s) {
    return nla_put(msgbuf, msgbuf_sz, off, type, s, (uint16_t)(strlen(s) + 1));
}

static int nla_nest_start(void *msgbuf, size_t msgbuf_sz, size_t *off, uint16_t type, size_t *nest_off_out) {
    // Create an attribute with no payload yet; fill length later.
    if (*off + NLA_ALIGN(NLA_HDRLEN) > msgbuf_sz) return -ENOBUFS;
    *nest_off_out = *off;
    struct nlattr_min *na = (struct nlattr_min *)((char *)msgbuf + *off);
    na->nla_type = type;
    na->nla_len  = (uint16_t)NLA_HDRLEN;
    *off += NLA_ALIGN(NLA_HDRLEN);
    return 0;
}
static void nla_nest_end(void *msgbuf, size_t *off, size_t nest_off) {
    struct nlattr_min *na = (struct nlattr_min *)((char *)msgbuf + nest_off);
    na->nla_len = (uint16_t)(*off - nest_off);
    // (already aligned by caller usage)
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

static void print_rate_info(const struct nlattr_min *rateinfo, const char *label) {
    // NL80211_ATTR_STA_INFO_{TX,RX}_BITRATE is nested with NL80211_RATE_INFO_*
    uint32_t bitrate100kbps = 0;
    bool have_bitrate = false;
    int rem = NLA_LEN(rateinfo);
    struct nlattr_min *na = (struct nlattr_min *)NLA_DATA(rateinfo);

    int mcs = -1;
    int width = -1;  // MHz
    bool sgi = false;

    for (; nla_ok(na, rem); na = nla_next(na, &rem)) {
        switch (na->nla_type) {
            case NL80211_RATE_INFO_BITRATE:
                // usually u16 in units of 100 kbit/s
                if (NLA_LEN(na) >= 2) {
                    bitrate100kbps = (uint32_t)get_u16_attr(na);
                    have_bitrate = true;
                }
                break;
            case NL80211_RATE_INFO_BITRATE32:
                bitrate100kbps = get_u32(na);
                have_bitrate = true;
                break;
            case NL80211_RATE_INFO_MCS:
                mcs = *(uint8_t *)NLA_DATA(na);
                break;
            case NL80211_RATE_INFO_40_MHZ_WIDTH:
                width = 40;
                break;
            case NL80211_RATE_INFO_80_MHZ_WIDTH:
                width = 80;
                break;
            case NL80211_RATE_INFO_80P80_MHZ_WIDTH:
                width = 160; // represent as 160-ish
                break;
            case NL80211_RATE_INFO_160_MHZ_WIDTH:
                width = 160;
                break;
            case NL80211_RATE_INFO_SHORT_GI:
                sgi = true;
                break;
            default:
                break;
        }
    }

    printf("  \"%s\": {", label);
    if (have_bitrate) {
        // nl80211 reports bitrate in units of 100 kbit/s
        double mbps = bitrate100kbps / 10.0;
        printf("\"mbps\": %.1f", mbps);
    } else {
        printf("\"mbps\": null");
    }
    printf(", \"mcs\": %s", (mcs >= 0 ? "" : "null"));
    if (mcs >= 0) printf("%d", mcs);

    printf(", \"width_mhz\": %s", (width > 0 ? "" : "null"));
    if (width > 0) printf("%d", width);

    printf(", \"sgi\": %s", sgi ? "true" : "false");
    printf("}");
}

static void print_chain_signal(const struct nlattr_min *chain_attr, const char *label) {
    // nested: entries of type NL80211_STA_INFO_CHAIN_SIGNAL / AVG:
    // each child has nla_type = chain index, payload s8 (dBm)
    int rem = NLA_LEN(chain_attr);
    struct nlattr_min *na = (struct nlattr_min *)NLA_DATA(chain_attr);

    printf("  \"%s\": [", label);
    bool first = true;
    for (; nla_ok(na, rem); na = nla_next(na, &rem)) {
        int8_t s = get_s8(na);
        if (!first) printf(", ");
        first = false;
        printf("%d", (int)s);
    }
    printf("]");
}

static void handle_station_msg(const struct nlmsghdr *h) {
    const struct genlmsghdr *g = (const struct genlmsghdr *)NLMSG_DATA(h);
    int rem = (int)(h->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN);
    struct nlattr_min *na = (struct nlattr_min *)((char *)g + GENL_HDRLEN);

    uint8_t mac[6] = {0};
    bool have_mac = false;

    // station fields
    uint64_t rx_bytes = 0, tx_bytes = 0;
    uint32_t rx_pkts = 0, tx_pkts = 0;
    uint32_t tx_retries = 0, tx_failed = 0;
    int8_t signal = 0, signal_avg = 0;
    bool have_signal = false, have_signal_avg = false;

    const struct nlattr_min *tx_rate = NULL;
    const struct nlattr_min *rx_rate = NULL;
    const struct nlattr_min *chain_sig = NULL;
    const struct nlattr_min *chain_sig_avg = NULL;

    uint32_t exp_thr = 0; // often in kbps
    bool have_exp_thr = false;

    const struct nlattr_min *sta_info = NULL;

    for (; nla_ok(na, rem); na = nla_next(na, &rem)) {
        switch (na->nla_type) {
            case NL80211_ATTR_MAC:
                if (NLA_LEN(na) >= 6) {
                    memcpy(mac, NLA_DATA(na), 6);
                    have_mac = true;
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
                case NL80211_STA_INFO_RX_BYTES64: rx_bytes = get_u64(si); break;
                case NL80211_STA_INFO_TX_BYTES64: tx_bytes = get_u64(si); break;
                case NL80211_STA_INFO_RX_BYTES:   rx_bytes = get_u32(si); break;
                case NL80211_STA_INFO_TX_BYTES:   tx_bytes = get_u32(si); break;
                case NL80211_STA_INFO_RX_PACKETS: rx_pkts = get_u32(si); break;
                case NL80211_STA_INFO_TX_PACKETS: tx_pkts = get_u32(si); break;
                case NL80211_STA_INFO_TX_RETRIES: tx_retries = get_u32(si); break;
                case NL80211_STA_INFO_TX_FAILED:  tx_failed = get_u32(si); break;
                case NL80211_STA_INFO_SIGNAL:     signal = get_s8(si); have_signal = true; break;
                case NL80211_STA_INFO_SIGNAL_AVG: signal_avg = get_s8(si); have_signal_avg = true; break;
                case NL80211_STA_INFO_TX_BITRATE: tx_rate = si; break;
                case NL80211_STA_INFO_RX_BITRATE: rx_rate = si; break;
                case NL80211_STA_INFO_CHAIN_SIGNAL: chain_sig = si; break;
                case NL80211_STA_INFO_CHAIN_SIGNAL_AVG: chain_sig_avg = si; break;
                case NL80211_STA_INFO_EXPECTED_THROUGHPUT:
                    exp_thr = get_u32(si);
                    have_exp_thr = true;
                    break;
                default:
                    break;
            }
        }
    }

    char macs[18] = "00:00:00:00:00:00";
    if (have_mac) mac_to_str(mac, macs);

    printf("{\n");
    printf("  \"mac\": \"%s\",\n", macs);
    printf("  \"rx_bytes\": %" PRIu64 ",\n", (uint64_t)rx_bytes);
    printf("  \"rx_packets\": %u,\n", rx_pkts);
    printf("  \"tx_bytes\": %" PRIu64 ",\n", (uint64_t)tx_bytes);
    printf("  \"tx_packets\": %u,\n", tx_pkts);
    printf("  \"tx_retries\": %u,\n", tx_retries);
    printf("  \"tx_failed\": %u,\n", tx_failed);

    if (have_signal)     printf("  \"signal_dbm\": %d,\n", (int)signal);
    else                 printf("  \"signal_dbm\": null,\n");
    if (have_signal_avg) printf("  \"signal_avg_dbm\": %d,\n", (int)signal_avg);
    else                 printf("  \"signal_avg_dbm\": null,\n");

    if (chain_sig) {
        print_chain_signal(chain_sig, "chain_signal_dbm");
        printf(",\n");
    } else {
        printf("  \"chain_signal_dbm\": null,\n");
    }
    if (chain_sig_avg) {
        print_chain_signal(chain_sig_avg, "chain_signal_avg_dbm");
        printf(",\n");
    } else {
        printf("  \"chain_signal_avg_dbm\": null,\n");
    }

    if (tx_rate) { print_rate_info(tx_rate, "tx_rate"); printf(",\n"); }
    else         { printf("  \"tx_rate\": null,\n"); }

    if (rx_rate) { print_rate_info(rx_rate, "rx_rate"); printf(",\n"); }
    else         { printf("  \"rx_rate\": null,\n"); }

    if (have_exp_thr) {
        // In many kernels it's in kbps.
        printf("  \"expected_throughput_kbps\": %u\n", exp_thr);
    } else {
        printf("  \"expected_throughput_kbps\": null\n");
    }
    printf("}\n");
}

static int nl80211_get_station(int fd, int nl80211_id, int ifindex, const uint8_t *mac_opt /* nullable */) {
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
            handle_station_msg(h);
        }

        if (mac_opt) {
            // Single query: usually one reply, no NLMSG_DONE
            return 0;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ifname> [peer-mac]\n", argv[0]);
        return 2;
    }

    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (ifindex <= 0) {
        fprintf(stderr, "if_nametoindex(%s) failed: %s\n", ifname, strerror(errno));
        return 1;
    }

    uint8_t mac[6];
    uint8_t *macp = NULL;
    if (argc >= 3) {
        if (!parse_mac(argv[2], mac)) {
            fprintf(stderr, "Invalid MAC: %s\n", argv[2]);
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

    int rc = nl80211_get_station(fd, nl80211_id, ifindex, macp);
    if (rc < 0) {
        fprintf(stderr, "GET_STATION failed: %s\n", strerror(-rc));
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
