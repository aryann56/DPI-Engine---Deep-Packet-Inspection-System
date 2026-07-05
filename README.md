# DPI Engine

A small Deep Packet Inspection engine in C++17. Reads a `.pcap` capture,
reconstructs each flow, pulls out the TLS SNI or HTTP Host header to figure
out what site/app a connection belongs to, and can block flows by rule.

Comes in two builds:
- **`dpi_simple`** - single-threaded, easiest to read, good starting point.
- **`dpi_mt`** - multi-threaded pipeline with per-flow load balancing and a
  lock-free fast-path cache per worker.

## Project structure

```
include/
  types.h              - FiveTuple, AppType, ParsedPacket, Flow
  pcap_reader.h         - .pcap file format structs + reader
  packet_parser.h       - Ethernet/IPv4/TCP/UDP header parsing
  sni_extractor.h        - TLS ClientHello SNI + HTTP Host parsing
  thread_safe_queue.h    - generic blocking queue (multi-thread build)
  rule_manager.h         - block-rule loading + matching (header-only)
  connection_tracker.h   - thread-safe flow table (header-only)
  load_balancer.h        - per-flow worker routing (header-only)
  fast_path.h            - per-worker classification cache (header-only)
  dpi_engine.h            - top-level multi-threaded pipeline (declaration)
src/
  types.cpp
  pcap_reader.cpp
  packet_parser.cpp
  sni_extractor.cpp
  main_working.cpp        - builds into dpi_simple
  dpi_mt.cpp               - builds into dpi_mt (implementation + main)
generate_test_pcap.py       - stdlib-only script to make a sample capture
```

## Building

Single-threaded version:
```bash
g++ -std=c++17 -O2 -Iinclude \
    src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp \
    src/sni_extractor.cpp src/main_working.cpp -o dpi_simple
```

Multi-threaded version:
```bash
g++ -std=c++17 -O2 -pthread -Iinclude \
    src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp \
    src/sni_extractor.cpp src/dpi_mt.cpp -o dpi_mt
```

## Generating a test capture

No real network capture needed - this builds one with hand-crafted TLS
ClientHello and HTTP packets:
```bash
python3 generate_test_pcap.py test_capture.pcap
```

## Running

```bash
./dpi_simple test_capture.pcap

./dpi_mt test_capture.pcap                 # no rules, default thread count
./dpi_mt test_capture.pcap rules.txt 4     # with rules, 4 worker threads
```

## Block rule file format

One rule per line, `#` for comments:
```
APP YOUTUBE
APP FACEBOOK
SNI doubleclick
IP  93.184.216.34
```
- `APP <NAME>` blocks every flow classified as that app (see `AppType` in `types.h`)
- `SNI <substring>` blocks any flow whose SNI/Host contains that substring
- `IP <a.b.c.d>` blocks any flow going to that destination IP

## How classification works

1. **Capture/dispatch**: each packet is parsed just enough to get its
   five-tuple (src/dst IP, src/dst port, protocol), then routed to a worker
   thread by hashing that tuple - so one flow always lands on the same thread.
2. **Slow path**: the first payload-bearing packet of a flow gets fully
   parsed; `SniExtractor` looks for a TLS ClientHello SNI extension first,
   then falls back to a plaintext HTTP `Host:` header.
3. **Fast path**: once a flow is classified, its decision (app type + block
   verdict) is cached per-worker. Later packets on the same flow skip
   straight to that cached decision - no locking needed, since a tuple never
   crosses threads.
4. **Reporting**: `ConnectionTracker` holds the final per-flow state; both
   builds print a sorted table of flows with packet counts, detected
   SNI/Host, classified app, and (for `dpi_mt`) block status.

## Notes / limitations

- IPv4 only - no IPv6 support.
- No TCP reassembly - a ClientHello or HTTP request split across multiple
  TCP segments won't be reassembled before parsing.
- Checksums aren't validated (parsing only cares about header field values).
- `generate_test_pcap.py` payloads are structurally valid but not
  cryptographically meaningful - they exist to exercise the parsers, not
  to represent a real handshake.
