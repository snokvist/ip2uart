# ip2uart

ip2uart is a lightweight bridge between a UART (or stdin/stdout) and a UDP peer. It batches
outbound UDP traffic, uses epoll-driven I/O, and can optionally inspect CRSF, MSP, and MAVLink
telemetry frames for basic logging.

## Features

- UART backend selectable between a serial device and standard input/output.
- UDP peer mode with optional coalescing thresholds for throughput-friendly batching.
- Reloadable configuration via `SIGHUP` and per-second verbose statistics when launched with `-v`.
- Optional CRSF/MSP/MAVLink frame detection and lightweight logging for telemetry data.

## Building

The provided Makefile is Buildroot-friendly and honors typical cross-compilation variables.

```sh
make CROSS_COMPILE=aarch64-linux-gnu-  # build the ip2uart binary
make clean                              # remove the built binary
```

## Installation

Use the `install` target to stage files into a root filesystem image or the live system.

```sh
make install DESTDIR=/tmp/rootfs PREFIX=/usr
```

The install step places the binary in `${PREFIX}/sbin`, the sample configuration in `/etc`, and the
init script in `/etc/init.d`. Files are stripped when `STRIP` is available via `CROSS_COMPILE`.

## Configuration

Runtime settings are read from `/etc/ip2uart.conf` by default. The file uses `key=value` pairs, and
unsupported entries are ignored. Important options include:

- `uart_backend`: `tty` or `stdio`.
- `uart_device`, `uart_baud`, `uart_databits`, `uart_parity`, `uart_stopbits`, `uart_flow` for
  serial configuration.
- `udp_bind_addr`, `udp_bind_port` to define the local socket.
- `udp_peer_addr`, `udp_peer_port` to lock to a peer; leave blank to auto-learn from inbound
  packets.
- `udp_coalesce_bytes`, `udp_coalesce_idle_ms`, `udp_max_datagram` to tune UDP batching.
- `telemetry_detect`, `crsf_log`, `crsf_log_path`, `crsf_log_rate_ms`, `crsf_coalesce` for
  telemetry support.
- `rx_buf`, `tx_buf` to size scratch buffers and ring buffers.

An example configuration is shipped as `ip2uart.conf`.

## Runtime hints

- Send `SIGHUP` to the process to reload the configuration and reopen file descriptors.
- Use `-v` one or more times to print one-line transfer statistics each second.
- When `telemetry_detect` is enabled, verbose mode reports per-type CRSF counters plus MSP and
  MAVLink frame counts for UART and UDP flows.
- Telemetry detection is per direction; once CRSF, MSP, or MAVLink is recognized, that parser is
  reused for the source while raw forwarding continues for other protocols so mixed telemetry can
  flow without disruption.
