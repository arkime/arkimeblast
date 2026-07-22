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

## Arkime reader plugin (`plugin/`)

The same packet generator can run **inside Arkime** as a capture reader, instead
of blasting a live NIC. Arkime then manufactures the traffic internally — no pcap
files, no interface — and processes it through its normal parse/session/ES path.
This is handy for deterministic test data: the same seed produces the exact same
packets, and (via a synthetic clock) the exact same timestamps, every run.

The generator sources in `src/` are reused unchanged; only `plugin/reader-synthetic.c`
is Arkime-specific. Arkime's `arkime_*` symbols are resolved at load time from the
capture binary, so nothing from Arkime is statically linked (`src/main.c` and the
AF_PACKET delivery layer are **not** part of the plugin).

### Build the plugin

Assumes an Arkime source checkout is available (defaults to `../../arkime`):

```
cd plugin
make ARKIME=/path/to/arkime      # -> plugin/reader-synthetic.so
```

### Run capture with it

The reader is selected with `pcapReadMethod=synthetic`. Because a reader must be
registered *before* the reader is chosen, the plugin has to be listed in
`rootPlugins=` (not `plugins=`). Run capture with **no** `-r`/`-R` so it takes the
live-reader path. All generator options go in a single `arkimeBlastCmdLine` string
using the same flags as the standalone tool:

```
capture/capture -c config.ini -n test \
    -o pcapReadMethod=synthetic \
    -o 'pluginsDir=/path/to/arkimeblast/plugin' \
    -o rootPlugins=reader-synthetic.so \
    -o packetThreads=1 \
    -o 'arkimeBlastCmdLine=--seed 42 --max-sessions 20 --mix http:100,https:0,dns:0'
```

After generating the requested traffic the reader calls `arkime_quit()`, so capture
flushes all sessions to Elasticsearch and exits cleanly (with several reader
threads, the last one to finish makes the call).

For fully reproducible output, keep `--reader-threads 1` (the default) **and**
set `packetThreads=1` — Arkime's per-packet thread assignment is salted with the
wall clock, so more than one packet thread can reorder session-to-thread mapping.

### Multiple reader threads

`--reader-threads N` (1–64, default 1) runs N independent generator threads, each
enqueueing into Arkime's packet threads the way a multi-queue live reader
(tpacketv3, netmap) does. Use it to put write pressure on capture's shared
counters and packet queues — with a single reader thread, contention that only
appears with several readers stays invisible.

Each thread gets its own rng stream (`seed + thread`), its own synthetic clock
(thread *t* starts at `base + t*delta` and steps by `delta*N`, so no two threads
ever emit the same timestamp), and its own share of `--max-sessions` /
`--max-packets` (thread 0 takes the remainder). So each thread is individually
reproducible and the total packet count for a given seed is stable, but the
threads interleave freely — the order packets reach capture, and therefore
Arkime's session-to-thread mapping, varies run to run.

### `arkimeBlastCmdLine` options

Honored: `--seed N`, `--mix http:..,https:..,dns:..`, `--subnet-src CIDR`,
`--subnet-dst CIDR`, `--max-packets N`.

Plugin-only: `--max-sessions N` (default 100; `0` = unbounded), `--reader-threads N`
(default 1, max 64), `--base-time SEC` (synthetic-clock start, default 1700000000),
`--time-delta US` (per-packet timestamp increment, default 100), `--run-forever`
(ignore counts / never auto-quit — load-test mode; stop with SIGINT).

Delivery-only flags (`--interface`, `--gbps`, `--threads`, `--duration`,
`--max-gb`, `--verbose`) are accepted and ignored, so a standalone blast command
line can be pasted in as-is.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
