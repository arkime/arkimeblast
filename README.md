# arkimeblast

High-performance traffic generator for testing [Arkime](https://arkime.com) packet capture and indexing at 20Gbps+.

Generates realistic HTTP, HTTPS, and DNS traffic using Linux AF_PACKET TX rings with zero-copy mmap'd sending across multiple threads.

## Features

- **20Gbps+ sustained throughput** using AF_PACKET TPACKET_V3 TX rings with `PACKET_QDISC_BYPASS`
- **Multi-threaded** — one AF_PACKET socket per thread, defaults to physical CPU core count
- **Full TCP sessions** — SYN → SYN-ACK → ACK → data → FIN with realistic retransmits (~1.5%) and drops (~0.5%)
- **Realistic HTTP traffic** — 50+ real User-Agent strings, randomized headers (Host, Accept, Accept-Language, Referer, Cookie, Cache-Control), varied response status codes
- **Multi-version TLS** — TLS 1.3 (70%), 1.2 (25%), 1.0/1.1 (5%) with diverse cipher suites, JA3/JA4-parseable ClientHellos, SNI, ALPN, certificates
- **Comprehensive DNS** — A, AAAA, MX, NS, TXT, CNAME, SOA, PTR query types with realistic distribution, EDNS0, multi-answer records, NXDOMAIN/SERVFAIL responses
- **Configurable traffic mix** — set ratios like `--mix http:60,https:30,dns:10`
- **Rate-limited** — token bucket per thread with `--gbps` target
- **Precise limits** — stop after N packets (`--max-packets`) or N gigabytes (`--max-gb`) with shared atomic counters
- **Random IPs** from configurable CIDR subnets
- **Reproducible** — seed-based RNG for deterministic traffic patterns

## Requirements

- Linux (AF_PACKET is Linux-only)
- GCC
- `CAP_NET_RAW` capability or root privileges

## Build

```bash
make
```

## Usage

```
arkimeblast [options]

  -i, --interface <iface>     Network interface to send on (required)
      --gbps <rate>           Target sending rate in Gbps (default: 1.0)
      --threads <N>           Number of sending threads (default: physical cores)
      --mix <proto:pct,...>   Traffic mix ratios (default: http:50,https:40,dns:10)
      --subnet-src <CIDR>     Source IP subnet (default: 10.0.0.0/8)
      --subnet-dst <CIDR>     Destination IP subnet (default: 172.16.0.0/12)
      --duration <seconds>    Run duration, 0=infinite (default: 0)
      --max-packets <N>       Stop after N packets (default: unlimited)
      --max-gb <N>            Stop after N gigabytes sent (default: unlimited)
      --seed <N>              RNG seed for reproducibility (default: 0)
  -v, --verbose               Print per-second stats
  -h, --help                  Show help
```

### Examples

```bash
# Send 20 Gbps of mixed traffic with live stats
sudo ./arkimeblast -i eth0 --gbps 20 -v

# Send exactly 1 million packets
sudo ./arkimeblast -i eth0 --gbps 10 --max-packets 1000000

# Send 100 GB of mostly HTTPS traffic
sudo ./arkimeblast -i eth0 --gbps 20 --max-gb 100 --mix http:10,https:80,dns:10

# DNS-only traffic at 5 Gbps for 60 seconds
sudo ./arkimeblast -i eth0 --gbps 5 --mix http:0,https:0,dns:100 --duration 60

# Reproducible test run
sudo ./arkimeblast -i eth0 --gbps 10 --seed 42 --max-packets 500000

# Run without sudo (set capability once)
sudo setcap cap_net_raw+ep ./arkimeblast
./arkimeblast -i eth0 --gbps 20 -v
```

### Sample Output

```
arkimeblast v0.1.0
  Interface:    eth0 (index 3)
  Target:       20.00 Gbps
  Threads:      16
  Mix:          http:50% https:40% dns:10%
  ...

Sending traffic... (Ctrl-C to stop)

[  18.4s] 72086870 pkts | 32.15 Gbps (avg 31.94) | 2562504 sess ...

╔══════════════════════════════════════════════╗
║           arkimeblast — Summary              ║
╠══════════════════════════════════════════════╣
║  Runtime:        00:00:18.40                 ║
║  Packets sent:   72086870                    ║
║  Bytes sent:     73560927440                 ║
║  Avg Gbps:       31.940                      ║
║  Peak Gbps:      33.120                      ║
║  ...                                         ║
╚══════════════════════════════════════════════╝
```

## Architecture

- **Main thread**: CLI parsing, thread spawning, signal handling (SIGINT/SIGTERM), stats aggregation
- **N worker threads**: each with its own AF_PACKET socket + mmap'd TX ring, independent RNG state, token bucket rate limiter
- **Session state machine**: each session progresses through protocol-appropriate TCP/UDP states
- **Zero external dependencies**: only libc and Linux kernel headers

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
