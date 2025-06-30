#!/bin/bash

# =========================================================================
# Enhanced PCAP Analysis Script for Incident Response (IR)
#
# Description:
# This script automates the analysis of a PCAP(NG) file with a focus on
# identifying suspicious activity and indicators of compromise (IOCs) often
# associated with malware. It uses tshark to extract key information.
#
# Author: Milind Bhargava
# Version: 2.0
# =========================================================================

# --- Configuration & Colors ---
set -e  # Exit immediately if a command exits with a non-zero status.
set -o pipefail # Causes a pipeline to return the exit status of the last command
                # that exited with a non-zero status.

# Add some colors for nicer output
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_BLUE='\033[0;34m'
C_NC='\033[0m' # No Color

# --- Initial Checks ---
PCAP="$1"
OUTPUT_DIR="pcap_analysis_$(basename "$PCAP" .pcapng)_$(date +%F_%H%M%S)"

# Check for tshark dependency
if ! command -v tshark &> /dev/null; then
    echo -e "${C_RED}[!] tshark could not be found. Please install it to continue.${C_NC}"
    echo "    On Debian/Ubuntu: sudo apt install tshark"
    echo "    On CentOS/RHEL:   sudo yum install wireshark"
    echo "    On macOS:         brew install wireshark"
    exit 1
fi

# Check for input file
if [[ -z "$PCAP" || ! -f "$PCAP" ]]; then
    echo -e "${C_RED}[!] Usage: $0 <capture.pcapng>${C_NC}"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo -e "${C_BLUE}[*] Starting analysis on: $PCAP${C_NC}"
echo -e "${C_BLUE}[*] Output will be stored in: $OUTPUT_DIR${C_NC}"

# --- Analysis Functions ---

analyze_general_stats() {
    echo -e "${C_YELLOW}[+] Generating General Statistics...${C_NC}"
    # Protocol hierarchy
    tshark -r "$PCAP" -q -z io,phs > "$OUTPUT_DIR/1_protocol_hierarchy.txt" 2>/dev/null
    # Packet length statistics
    tshark -r "$PCAP" -q -z io,stat,1 > "$OUTPUT_DIR/2_packet_size_distribution.txt" 2>/dev/null
    # Conversation endpoints
    tshark -r "$PCAP" -q -z endpoints,ip > "$OUTPUT_DIR/3_ip_endpoints.txt" 2>/dev/null
    tshark -r "$PCAP" -q -z conv,tcp > "$OUTPUT_DIR/4_tcp_conversations.txt" 2>/dev/null
    tshark -r "$PCAP" -q -z conv,udp > "$OUTPUT_DIR/5_udp_conversations.txt" 2>/dev/null
}

analyze_dns() {
    echo -e "${C_YELLOW}[+] Analyzing DNS Queries...${C_NC}"
    tshark -r "$PCAP" -Y "dns.qry.name" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e dns.qry.name \
        -e dns.a \
        -e dns.cname \
        -E header=y -E separator=, > "$OUTPUT_DIR/dns_queries.csv" 2>/dev/null || echo "No DNS queries found."
}

analyze_http() {
    echo -e "${C_YELLOW}[+] Analyzing HTTP/HTTP2 Traffic...${C_NC}"
    # HTTP Requests
    tshark -r "$PCAP" -Y "http.request or http2.headers.method" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e tcp.dstport \
        -e http.request.method \
        -e http.host \
        -e http.request.uri \
        -E header=y -E separator=, > "$OUTPUT_DIR/http_requests.csv" 2>/dev/null || echo "No HTTP requests found."

    # User-Agents
    tshark -r "$PCAP" -Y "http.user_agent" -T fields -e http.user_agent \
        | sort | uniq -c | sort -nr > "$OUTPUT_DIR/http_user_agents_summary.txt" 2>/dev/null || echo "No User-Agents found."
}

analyze_tls() {
    echo -e "${C_YELLOW}[+] Analyzing TLS/SSL Certificates and Fingerprints (JA3)...${C_NC}"
    # JA3 Hashes are excellent for fingerprinting client applications (malware)
    tshark -r "$PCAP" -Y "tls.handshake.type == 1" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e tcp.dstport \
        -e tls.handshake.ja3 \
        -e tls.handshake.ja3s \
        -e tls.handshake.extensions.server_name \
        -E header=y -E separator=, > "$OUTPUT_DIR/tls_ja3_fingerprints.csv" 2>/dev/null || echo "No TLS Client Hellos found."
}

analyze_smb() {
    echo -e "${C_YELLOW}[+] Analyzing SMB/SMB2 File Transfers...${C_NC}"
    tshark -r "$PCAP" -Y "smb2.filename" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e smb2.filename \
        -e smb2.tree \
        -E header=y -E separator=, > "$OUTPUT_DIR/smb2_filenames.csv" 2>/dev/null || echo "No SMB2 filenames found."
}

extract_files() {
    echo -e "${C_YELLOW}[+] Exporting Transferred Files (HTTP, SMB, FTP, etc.)...${C_NC}"
    mkdir -p "$OUTPUT_DIR/exported_files"
    # This command uses tshark's built-in object exporter, which is far more reliable.
    tshark --export-objects "http,smb,imf,tftp,dicom" -r "$PCAP" --export-objects-dir "$OUTPUT_DIR/exported_files" >/dev/null 2>&1 || echo "Could not export files or no files found."
    echo -e "    ${C_GREEN}Exported files are in '$OUTPUT_DIR/exported_files'${C_NC}"
}

extract_streams() {
    echo -e "${C_YELLOW}[+] Extracting TCP Streams (Efficient Method)...${C_NC}"
    mkdir -p "$OUTPUT_DIR/tcp_streams"
    # Get a unique, sorted list of stream indices present in the capture
    STREAM_INDICES=$(tshark -r "$PCAP" -T fields -e tcp.stream | sort -n | uniq)
    if [ -n "$STREAM_INDICES" ]; then
        for i in $STREAM_INDICES; do
            tshark -r "$PCAP" -q -z "follow,tcp,ascii,$i" > "$OUTPUT_DIR/tcp_streams/stream_$i.txt"
        done
        echo -e "    ${C_GREEN}Extracted $(echo "$STREAM_INDICES" | wc -l | xargs) TCP streams to '$OUTPUT_DIR/tcp_streams'${C_NC}"
    else
        echo "No TCP streams found to extract."
    fi
}


# --- Main Execution ---
main() {
    analyze_general_stats
    analyze_dns
    analyze_http
    analyze_tls
    analyze_smb
    extract_files
    extract_streams

    echo -e "\n${C_GREEN}[+] Analysis complete. Artifacts stored in '$OUTPUT_DIR'${C_NC}"
}

# Run the analysis
main
