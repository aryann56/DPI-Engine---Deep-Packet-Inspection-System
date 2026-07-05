#!/usr/bin/env python3
"""
generate_test_pcap.py

Builds a small hand-crafted .pcap file for testing the DPI engine.
Pure Python standard library only - no scapy/dpkt dependency, so it
runs anywhere Python 3 does.

Included flows:
  1. TLS ClientHello with SNI "www.google.com"     (HTTPS, port 443)
  2. TLS ClientHello with SNI "www.youtube.com"     (HTTPS, port 443)
  3. TLS ClientHello with SNI "www.facebook.com"    (HTTPS, port 443)
  4. Plaintext HTTP GET, Host: example.com          (HTTP,  port 80)
  5. A UDP packet to port 53                        (DNS-looking, unparsed payload)

Run:
    python3 generate_test_pcap.py test_capture.pcap

Then, e.g.:
    ./dpi_simple test_capture.pcap
    ./dpi_mt    test_capture.pcap rules.txt 4
"""

import struct
import sys

# ---------------- low-level header builders ----------------

def eth_header(dst_mac: bytes, src_mac: bytes, ethertype: int = 0x0800) -> bytes:
    return struct.pack("!6s6sH", dst_mac, src_mac, ethertype)


def ipv4_header(src_ip: bytes, dst_ip: bytes, proto: int, payload_len: int,
                 ttl: int = 64, ident: int = 1) -> bytes:
    version_ihl = (4 << 4) | 5   # IPv4, 20-byte header (no options)
    total_len = 20 + payload_len
    flags_frag = 0
    checksum = 0  # our parser doesn't validate checksums, 0 is fine
    return struct.pack("!BBHHHBBH4s4s",
                        version_ihl, 0, total_len, ident, flags_frag,
                        ttl, proto, checksum,
                        src_ip, dst_ip)


def tcp_header(src_port: int, dst_port: int, seq: int = 1000, ack: int = 0,
                flags: int = 0x18, window: int = 8192) -> bytes:
    data_offset = (5 << 4)  # 20-byte header, no options
    checksum = 0
    urg_ptr = 0
    return struct.pack("!HHLLBBHHH",
                        src_port, dst_port, seq, ack,
                        data_offset, flags, window, checksum, urg_ptr)


def udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    length = 8 + payload_len
    checksum = 0
    return struct.pack("!HHHH", src_port, dst_port, length, checksum)


def ip_to_bytes(ip_str: str) -> bytes:
    return bytes(int(octet) for octet in ip_str.split("."))


# ---------------- payload builders ----------------

def build_tls_client_hello_sni(hostname: str) -> bytes:
    """Minimal, structurally-valid TLS 1.2 ClientHello containing only
    a server_name (SNI) extension - enough for SniExtractor to parse."""
    hostname_bytes = hostname.encode("ascii")

    sni_entry = struct.pack("!BH", 0, len(hostname_bytes)) + hostname_bytes   # name_type=hostname
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    ext_server_name = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list    # extension type 0 = SNI

    extensions_block = struct.pack("!H", len(ext_server_name)) + ext_server_name

    client_version = struct.pack("!H", 0x0303)     # "TLS 1.2" in ClientHello.version
    random_bytes = bytes(32)                        # zeroed - fine for test data
    session_id = struct.pack("!B", 0)                # empty session id
    cipher_suites = struct.pack("!H", 2) + struct.pack("!H", 0x1301)  # one cipher suite
    compression = struct.pack("!BB", 1, 0)           # one method: null

    body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_block

    handshake_header = struct.pack("!B", 1) + len(body).to_bytes(3, "big")  # 1 = ClientHello
    handshake = handshake_header + body

    record_header = struct.pack("!BHH", 0x16, 0x0301, len(handshake))  # 0x16 = Handshake record
    return record_header + handshake


def build_http_get(host: str) -> bytes:
    request = (f"GET / HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"User-Agent: test-client\r\n"
               f"Connection: close\r\n\r\n")
    return request.encode("ascii")


# ---------------- packet assembly ----------------

def build_packet(src_mac: bytes, dst_mac: bytes, src_ip: str, dst_ip: str,
                  proto: int, src_port: int, dst_port: int, payload: bytes,
                  flags: int = 0x18) -> bytes:
    eth = eth_header(dst_mac, src_mac)
    if proto == 6:  # TCP
        transport = tcp_header(src_port, dst_port, flags=flags)
    else:           # UDP
        transport = udp_header(src_port, dst_port, len(payload))
    ip = ipv4_header(ip_to_bytes(src_ip), ip_to_bytes(dst_ip), proto,
                      len(transport) + len(payload))
    return eth + ip + transport + payload


# ---------------- pcap container ----------------

def pcap_global_header() -> bytes:
    magic = 0xa1b2c3d4
    return struct.pack("<IHHiIII",
                        magic,     # magic_number
                        2, 4,      # version_major, version_minor
                        0, 0,      # thiszone, sigfigs
                        65535,     # snaplen
                        1)         # network = 1 (Ethernet)


def pcap_record_header(ts_sec: int, ts_usec: int, length: int) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, length, length)


def write_pcap(filename: str, packets: list):
    with open(filename, "wb") as f:
        f.write(pcap_global_header())
        ts_sec = 1_700_000_000  # arbitrary fixed start time
        for i, pkt in enumerate(packets):
            f.write(pcap_record_header(ts_sec, i * 1000, len(pkt)))
            f.write(pkt)


# ---------------- main ----------------

def main():
    out_file = sys.argv[1] if len(sys.argv) > 1 else "test_capture.pcap"

    CLIENT_MAC = bytes.fromhex("aabbccdd0001")
    SERVER_MAC = bytes.fromhex("aabbccdd0002")
    CLIENT_IP = "10.0.0.5"

    packets = []

    # Flow 1: SYN then TLS ClientHello -> www.google.com
    packets.append(build_packet(CLIENT_MAC, SERVER_MAC, CLIENT_IP, "142.250.190.100",
                                 6, 51000, 443, b"", flags=0x02))  # SYN
    packets.append(build_packet(CLIENT_MAC, SERVER_MAC, CLIENT_IP, "142.250.190.100",
                                 6, 51000, 443, build_tls_client_hello_sni("www.google.com")))

    # Flow 2: TLS ClientHello -> www.youtube.com
    packets.append(build_packet(CLIENT_MAC, SERVER_MAC, CLIENT_IP, "13.107.42.14",
                                 6, 51001, 443, b"", flags=0x02))
    packets.append(build_packet(CLIENT_MAC, SERVER_MAC, CLIENT_IP, "13.107.42.14",
                                 6, 51001, 443, build_tls_client_hello_sni("www.youtube.com")))

    # Flow 3: TLS ClientHello -> www.facebook.com (handy for testing block rules)
    packets.append(build_packet(CLIENT_MAC, SERVER_MAC, CLIENT_IP, "157.240.22.35",
                                 6, 51002, 443, b"", flags=0x02))
    packets.append(build_packet(CLIENT_MAC, SERVER_MAC, CLIENT_IP, "157.240.22.35",
                                 6, 51002, 443, build_tls_client_hello_sni("www.facebook.com")))

    # Flow 4: plaintext HTTP GET, Host: example.com
    packets.append(build_packet(CLIENT_MAC, SERVER_MAC, CLIENT_IP, "93.184.216.34",
                                 6, 51003, 80, b"", flags=0x02))
    packets.append(build_packet(CLIENT_MAC, SERVER_MAC, CLIENT_IP, "93.184.216.34",
                                 6, 51003, 80, build_http_get("example.com")))

    # Flow 5: a plain UDP packet (e.g. DNS) - payload content isn't parsed
    packets.append(build_packet(CLIENT_MAC, SERVER_MAC, CLIENT_IP, "8.8.8.8",
                                 17, 33333, 53, b"\x00" * 12))

    # A couple of extra ACK-only packets on flow 1, to show packet_count > 1
    # and exercise the fast-path cache (same tuple, already classified).
    packets.append(build_packet(CLIENT_MAC, SERVER_MAC, CLIENT_IP, "142.250.190.100",
                                 6, 51000, 443, b"", flags=0x10))
    packets.append(build_packet(CLIENT_MAC, SERVER_MAC, CLIENT_IP, "142.250.190.100",
                                 6, 51000, 443, b"", flags=0x10))

    write_pcap(out_file, packets)
    print(f"Wrote {len(packets)} packets to {out_file}")


if __name__ == "__main__":
    main()
