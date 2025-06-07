#!/bin/bash

# -----------------------------
# Automated PCAPNG Analysis for IR (Malware-Focused)
# -----------------------------
PCAP="$1"
OUTPUT_DIR="pcap_analysis_$(date +%F_%H%M%S)"

if [[ -z "$PCAP" || ! -f "$PCAP" ]]; then
  echo "[!] Usage: $0 capture.pcapng"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting analysis on $PCAP"
echo "[*] Output directory: $OUTPUT_DIR"

# Protocol hierarchy
tshark -r "$PCAP" -q -z io,phs > "$OUTPUT_DIR/protocol_hierarchy.txt"

# Top talkers
tshark -r "$PCAP" -T fields -e ip.src | sort | uniq -c | sort -nr > "$OUTPUT_DIR/top_sources.txt"
tshark -r "$PCAP" -T fields -e ip.dst | sort | uniq -c | sort -nr > "$OUTPUT_DIR/top_destinations.txt"

# HTTP Requests
tshark -r "$PCAP" -Y "http.request" -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri > "$OUTPUT_DIR/http_requests.txt"

# DNS Queries
tshark -r "$PCAP" -Y dns -T fields -e frame.time -e ip.src -e dns.qry.name > "$OUTPUT_DIR/dns_queries.txt"

# TCP Conversations
tshark -r "$PCAP" -q -z conv,tcp > "$OUTPUT_DIR/tcp_conversations.txt"

# Extract User-Agent headers
tshark -r "$PCAP" -Y "http.request" -T fields -e http.user_agent | sort | uniq -c | sort -nr > "$OUTPUT_DIR/http_user_agents.txt"

# Export all TCP streams
mkdir "$OUTPUT_DIR/tcp_streams"
MAX_STREAM=$(tshark -r "$PCAP" -T fields -e tcp.stream | sort -n | uniq | tail -1)
for i in $(seq 0 "$MAX_STREAM"); do
  tshark -r "$PCAP" -q -z "follow,tcp,ascii,$i" > "$OUTPUT_DIR/tcp_streams/stream_$i.txt"
done

# Packet size distribution
tshark -r "$PCAP" -q -z io,stat,1 > "$OUTPUT_DIR/packet_sizes.txt"

# Extract known file transfers (HTTP or SMB)
tshark -r "$PCAP" -Y "http.content_type || smb" > "$OUTPUT_DIR/possible_file_transfers.txt"

echo "[+] Analysis complete. Artifacts stored in $OUTPUT_DIR"
