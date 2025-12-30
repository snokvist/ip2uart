// msp_output.c
// MSP telemetry sniffer on a Betaflight MSP DisplayPort UART.
//
// - Opens /dev/ttyS2 @ 115200 8N1 (or device from argv[1])
// - Shares the MSP bus with MSP DisplayPort (182) – ignores DisplayPort spam
// - Periodically sends MSP requests for:
//     MSP_ANALOG (110)
//     MSP_STATUS_EX (150)
//     MSP_RAW_GPS (106)
//     MSP_COMP_GPS (107)
//     MSP_ALTITUDE (109)
// - Maintains latest values in a telemetry struct
// - Prints a single combined summary line at ~5 Hz.
//
// Build:  gcc -O2 -Wall -o msp_output msp_output.c
// Run:    ./msp_output          # uses /dev/ttyS2
//         ./msp_output /dev/ttyUSB0

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>
#include <time.h>

// ---------------- MSP IDs ----------------

#define MSP_RAW_GPS      106
#define MSP_COMP_GPS     107
#define MSP_ALTITUDE     109
#define MSP_ANALOG       110
#define MSP_STATUS_EX    150
#define MSP_DISPLAYPORT  182

// ---------------- MSP payload structs ----------------

#pragma pack(push, 1)

typedef struct {
    uint8_t  vbat;       // 0.1 V units
    uint16_t mAhDrawn;
    uint16_t rssi;       // 0..1023 or 0..1000
    int16_t  amperage;   // 0.01 A units
} msp_analog_t;

typedef struct {
    uint16_t cycleTime;
    uint16_t i2cErrorCounter;
    uint16_t sensor;
    uint32_t flightModeFlags;
    uint8_t  configProfileIndex;
    uint16_t averageSystemLoadPercent;
    uint16_t armingFlags;
    uint8_t  accCalibrationAxisFlags;
} msp_status_ex_t;

typedef struct {
    uint8_t  fixType;       // 0=no, 1=2D, 2=3D
    uint8_t  numSat;
    int32_t  lat;           // 1 / 10^7 deg
    int32_t  lon;           // 1 / 10^7 deg
    int16_t  alt;           // meters
    int16_t  groundSpeed;   // cm/s
    int16_t  groundCourse;  // deg * 10
    uint16_t hdop;
} msp_raw_gps_t;

typedef struct {
    int16_t  distanceToHome;  // meters
    int16_t  directionToHome; // deg
    uint8_t  heartbeat;
} msp_comp_gps_t;

// Betaflight MSP_ALTITUDE: 6 bytes (int32 altitude_cm, int16 vario_cm_s)
typedef struct {
    int32_t altitude_cm;
    int16_t vario_cm_s;
} msp_altitude_t;

#pragma pack(pop)

// ---------------- Flight mode flags bits ----------------

#define MSP_MODE_ARM          0
#define MSP_MODE_ANGLE        1
#define MSP_MODE_HORIZON      2
#define MSP_MODE_NAVRTH       8
#define MSP_MODE_NAVPOSHOLD   9
#define MSP_MODE_AIRMODE      21

// ---------------- Arming flags ----------------

#define ARMING_FLAG_ARMED     (1u << 2)

// ---------------- Telemetry state ----------------

typedef struct {
    double   vbat_v;
    uint16_t mAh;
    uint16_t rssi;
    double   current_a;
    double   power_w;

    int      armed;
    char     mode[16];
    uint16_t cpu_load;

    uint8_t  gps_fix;
    uint8_t  gps_sats;
    double   gps_lat_deg;
    double   gps_lon_deg;
    double   gps_alt_m;
    double   gps_speed_kmh;
    double   gps_course_deg;
    uint16_t gps_hdop;

    int16_t  home_dist_m;
    int16_t  home_dir_deg;
    uint8_t  home_heartbeat;

    double   alt_baro_m;
    double   vSpeed_ms;
} telemetry_t;

static telemetry_t g_telemetry;

// ---------------- Time helpers ----------------

static double now_monotonic_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

// ---------------- Serial helper ----------------

static int open_serial(const char *dev)
{
    int fd = open(dev, O_RDWR | O_NOCTTY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    struct termios tio;
    if (tcgetattr(fd, &tio) < 0) {
        perror("tcgetattr");
        close(fd);
        return -1;
    }

    cfmakeraw(&tio);
    cfsetispeed(&tio, B115200);
    cfsetospeed(&tio, B115200);

    tio.c_cflag |= (CLOCAL | CREAD);
    tio.c_cflag &= ~CSIZE;
    tio.c_cflag |= CS8;
    tio.c_cflag &= ~PARENB;
    tio.c_cflag &= ~CSTOPB;

    if (tcsetattr(fd, TCSANOW, &tio) < 0) {
        perror("tcsetattr");
        close(fd);
        return -1;
    }

    return fd;
}

// ---------------- MSP helpers ----------------

static const char *flight_mode_from_flags(uint32_t flags)
{
    if (flags & (1u << MSP_MODE_ANGLE))        return "ANGLE";
    if (flags & (1u << MSP_MODE_HORIZON))      return "HORIZON";
    if (flags & (1u << MSP_MODE_NAVRTH))       return "RESCUE";
    if (flags & (1u << MSP_MODE_NAVPOSHOLD))   return "POSHOLD";
    if (flags & (1u << MSP_MODE_AIRMODE))      return "ACRO+AIR";
    if (flags & (1u << MSP_MODE_ARM))          return "ACRO";
    return "DISARM";
}

static int send_msp_v1(int fd, uint8_t cmd, const uint8_t *payload, uint8_t size)
{
    if (size > 255) return -1;

    uint8_t buf[3 + 1 + 1 + 255 + 1];

    buf[0] = '$';
    buf[1] = 'M';
    buf[2] = '<';
    buf[3] = size;
    buf[4] = cmd;

    uint8_t csum = size ^ cmd;

    for (uint8_t i = 0; i < size; i++) {
        uint8_t v = payload ? payload[i] : 0;
        buf[5 + i] = v;
        csum ^= v;
    }
    buf[5 + size] = csum;

    ssize_t total = 3 + 1 + 1 + size + 1; // "$M<" + size + cmd + payload + checksum
    ssize_t n = write(fd, buf, total);
    if (n != total) {
        perror("write MSP");
        return -1;
    }
    return 0;
}

// ---------------- MSP parser state ----------------

typedef enum {
    MSP_STATE_IDLE = 0,
    MSP_STATE_HEADER_M,
    MSP_STATE_HEADER_DIR,
    MSP_STATE_SIZE,
    MSP_STATE_CMD,
    MSP_STATE_PAYLOAD,
    MSP_STATE_CHECKSUM
} msp_state_t;

#define MSP_MAX_PAYLOAD 512

// ---------------- Handle decoded MSP messages ----------------

static void handle_msp(uint8_t cmd, uint8_t *payload, uint8_t size)
{
    switch (cmd) {
    case MSP_ANALOG:
        if (size >= sizeof(msp_analog_t)) {
            msp_analog_t a;
            memcpy(&a, payload, sizeof(a));

            g_telemetry.vbat_v    = a.vbat / 10.0;
            g_telemetry.mAh       = a.mAhDrawn;
            g_telemetry.rssi      = a.rssi;
            g_telemetry.current_a = a.amperage / 100.0;
            g_telemetry.power_w   = g_telemetry.vbat_v * g_telemetry.current_a;
        }
        break;

    case MSP_STATUS_EX:
        if (size >= sizeof(msp_status_ex_t)) {
            msp_status_ex_t s;
            memcpy(&s, payload, sizeof(s));

            g_telemetry.armed = (s.armingFlags & ARMING_FLAG_ARMED) ? 1 : 0;
            g_telemetry.cpu_load = s.averageSystemLoadPercent;
            const char *mode = flight_mode_from_flags(s.flightModeFlags);
            snprintf(g_telemetry.mode, sizeof(g_telemetry.mode), "%s", mode);
        }
        break;

    case MSP_RAW_GPS:
        if (size >= sizeof(msp_raw_gps_t)) {
            msp_raw_gps_t g;
            memcpy(&g, payload, sizeof(g));

            g_telemetry.gps_fix       = g.fixType;
            g_telemetry.gps_sats      = g.numSat;
            g_telemetry.gps_lat_deg   = g.lat / 1e7;
            g_telemetry.gps_lon_deg   = g.lon / 1e7;
            g_telemetry.gps_alt_m     = g.alt;
            double spd_ms             = g.groundSpeed / 100.0;
            g_telemetry.gps_speed_kmh = spd_ms * 3.6;
            g_telemetry.gps_course_deg= g.groundCourse / 10.0;
            g_telemetry.gps_hdop      = g.hdop;
        }
        break;

    case MSP_COMP_GPS:
        if (size >= sizeof(msp_comp_gps_t)) {
            msp_comp_gps_t c;
            memcpy(&c, payload, sizeof(c));

            g_telemetry.home_dist_m   = c.distanceToHome;
            g_telemetry.home_dir_deg  = c.directionToHome;
            g_telemetry.home_heartbeat= c.heartbeat;
        }
        break;

    case MSP_ALTITUDE:
        if (size >= sizeof(msp_altitude_t)) {
            msp_altitude_t a;
            memcpy(&a, payload, sizeof(a));

            g_telemetry.alt_baro_m = a.altitude_cm / 100.0;
            g_telemetry.vSpeed_ms  = a.vario_cm_s / 100.0;
        }
        break;

    case MSP_DISPLAYPORT:
        // Ignored (OSD draw commands to VTX).
        break;

    default:
        // Unused for now
        break;
    }
}

// ---------------- Print combined summary ----------------

static void print_summary(void)
{
    printf("VBAT=%.2fV mAh=%u RSSI=%u "
           "armed=%s mode=%s CPU=%u%% "
           "alt=%.2fm vSpd=%.2fm/s",
           g_telemetry.vbat_v,
           g_telemetry.mAh,
           g_telemetry.rssi,
           g_telemetry.armed ? "YES" : "NO",
           g_telemetry.mode[0] ? g_telemetry.mode : "UNK",
           g_telemetry.cpu_load,
           g_telemetry.alt_baro_m,
           g_telemetry.vSpeed_ms);

    // Append GPS if we ever have a fix or sats > 0
    if (g_telemetry.gps_sats > 0 || g_telemetry.gps_fix > 0) {
        printf(" GPSfix=%u sats=%u lat=%.7f lon=%.7f "
               "gAlt=%.1fm gSpd=%.1fkm/h gCourse=%.1fdeg "
               "homeDist=%dm homeDir=%ddeg",
               g_telemetry.gps_fix,
               g_telemetry.gps_sats,
               g_telemetry.gps_lat_deg,
               g_telemetry.gps_lon_deg,
               g_telemetry.gps_alt_m,
               g_telemetry.gps_speed_kmh,
               g_telemetry.gps_course_deg,
               g_telemetry.home_dist_m,
               g_telemetry.home_dir_deg);
    }

    printf("\n");
    fflush(stdout);
}

// ---------------- main ----------------

int main(int argc, char **argv)
{
    const char *dev = "/dev/ttyS2";
    if (argc > 1) {
        dev = argv[1];
    }

    memset(&g_telemetry, 0, sizeof(g_telemetry));

    int fd = open_serial(dev);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s\n", dev);
        return 1;
    }

    fprintf(stderr,
            "Listening for MSP on %s @ 115200 (DisplayPort + telemetry).\n"
            "Sending periodic MSP requests and printing combined summary.\n",
            dev);

    msp_state_t state = MSP_STATE_IDLE;
    uint8_t dir = 0;
    uint8_t size = 0;
    uint8_t cmd = 0;
    uint8_t payload[MSP_MAX_PAYLOAD];
    uint8_t checksum = 0;
    uint8_t payload_pos = 0;

    double last_req_time   = 0.0;
    double last_print_time = 0.0;
    const double req_interval   = 0.2;  // 5 Hz MSP request
    const double print_interval = 0.2;  // 5 Hz output

    for (;;) {
        double t_now = now_monotonic_s();

        // Periodically send MSP requests
        if (t_now - last_req_time >= req_interval) {
            last_req_time = t_now;
            send_msp_v1(fd, MSP_ANALOG,    NULL, 0);
            send_msp_v1(fd, MSP_STATUS_EX, NULL, 0);
            send_msp_v1(fd, MSP_RAW_GPS,   NULL, 0);
            send_msp_v1(fd, MSP_COMP_GPS,  NULL, 0);
            send_msp_v1(fd, MSP_ALTITUDE,  NULL, 0);
        }

        // Periodic summary print
        if (t_now - last_print_time >= print_interval) {
            last_print_time = t_now;
            print_summary();
        }

        // Wait for data with a short timeout
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 50000; // 50 ms

        int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        if (ret == 0) {
            continue; // timeout
        }
        if (!FD_ISSET(fd, &rfds)) {
            continue;
        }

        uint8_t b;
        ssize_t n = read(fd, &b, 1);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN))
                continue;
            perror("read");
            break;
        }

        // MSP v1 parser
        switch (state) {
        case MSP_STATE_IDLE:
            if (b == '$') {
                state = MSP_STATE_HEADER_M;
            }
            break;

        case MSP_STATE_HEADER_M:
            if (b == 'M') {
                state = MSP_STATE_HEADER_DIR;
            } else {
                state = MSP_STATE_IDLE;
            }
            break;

        case MSP_STATE_HEADER_DIR:
            if (b == '<' || b == '>' || b == '!') {
                dir = b;
                state = MSP_STATE_SIZE;
            } else {
                state = MSP_STATE_IDLE;
            }
            break;

        case MSP_STATE_SIZE:
            size = b;
            if (size > MSP_MAX_PAYLOAD) {
                state = MSP_STATE_IDLE;
            } else {
                checksum = 0;
                checksum ^= size;
                state = MSP_STATE_CMD;
            }
            break;

        case MSP_STATE_CMD:
            cmd = b;
            checksum ^= cmd;
            payload_pos = 0;
            if (size == 0) {
                state = MSP_STATE_CHECKSUM;
            } else {
                state = MSP_STATE_PAYLOAD;
            }
            break;

        case MSP_STATE_PAYLOAD:
            payload[payload_pos++] = b;
            checksum ^= b;
            if (payload_pos >= size) {
                state = MSP_STATE_CHECKSUM;
            }
            break;

        case MSP_STATE_CHECKSUM:
            if (checksum == b && dir == '>') {
                handle_msp(cmd, payload, size);
            }
            state = MSP_STATE_IDLE;
            break;
        }
    }

    close(fd);
    return 0;
}
