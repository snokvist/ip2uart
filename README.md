# ip2uart

ip2uart is a lightweight bridge between a serial UART and a UDP peer.
It batches outbound UDP traffic, uses epoll-driven I/O, and can inspect CRSF,
MSP, or MAVLink telemetry frames for verbose troubleshooting output.

## Features

- UART TTY backend for embedded serial devices.
- UDP peer mode with coalescing thresholds for throughput-friendly batching.
- Reloadable configuration via `SIGHUP`.
- Per-second transfer statistics when launched with `-v`.
- Optional telemetry parsing for CRSF, MSP, or MAVLink in verbose mode.

## Building

The provided Makefile is Buildroot-friendly and honors typical
cross-compilation variables.

```sh
make CROSS_COMPILE=aarch64-linux-gnu-  # build the ip2uart binary
make clean                              # remove the built binary
```

## Installation

Use the `install` target to stage files into a root filesystem image or the
live system.

```sh
make install DESTDIR=/tmp/rootfs PREFIX=/usr
```

The install step places the binary in `${PREFIX}/bin`, the sample
configuration in `/etc`, and the init script in `/etc/init.d`.
Files are stripped when `STRIP` is available via `CROSS_COMPILE`.

## Configuration

Runtime settings are read from `/etc/ip2uart.conf` by default.
The file uses `key=value` pairs, and unsupported entries are ignored.

Important options include:

- `uart_device`, `uart_baud`, `uart_databits`, `uart_parity`,
  `uart_stopbits`, `uart_flow` for serial configuration.
- `udp_bind_addr`, `udp_bind_port` to define the local socket.
- `udp_peer_addr`, `udp_peer_port` to lock to a peer.
  Leave the peer address blank to auto-learn from inbound packets.
- `udp_coalesce_bytes`, `udp_coalesce_idle_ms`, `udp_max_datagram`
  to tune UDP batching.
- `telemetry_proto` (`off`, `crsf`, `msp`, or `mavlink`) to select parser mode.
- `telemetry_coalesce` to control frame coalescing behavior in telemetry mode.
- `telemetry_msp_rate` to control MSP polling frequency in MSP mode.
- `rx_buf`, `tx_buf` to size scratch buffers and ring buffers.

An example configuration is shipped as `ip2uart.conf`.

## Runtime hints

- Send `SIGHUP` to reload configuration and reopen file descriptors.
- Use `-v` one or more times to print one-line transfer statistics each second.
- In telemetry mode, verbose output reports protocol counters by direction.
