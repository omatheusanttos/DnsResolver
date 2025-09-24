# 🔍 Dns Resolver

A fast and efficient subdomain and HTTP/HTTPS scanner designed to help CTI teams or pentesters identify active subdomains and validate web services.

This script combines:

  - DNS enumeration (`A`, `AAAA`, `MX`, `NS`) using multiple reliable servers (`1.1.1.1`, `8.8.8.8`).
  - Wildcard DNS detection to avoid false positives.
  - HTTP/HTTPS validation with status, IP, and redirects.
  - Parallel execution with threads for optimized speed.

-----

## ⚙️ Key Features

1.  Subdomain discovery using a wordlist.
2.  Automatic wildcard DNS detection.
3.  HTTP/HTTPS service validation for found subdomains.
4.  DNS caching to avoid repeated queries.
5.  Configurable multithreading for both DNS and HTTP.
6.  File output:
       - `dns_results.txt` → found subdomains + record type.
       - `alive_subs_ips.txt` → online subdomains with HTTP/HTTPS status and IP.

-----

## 🚀 How to Use

### 1\. Clone the repository:

```shell
git clone https://github.com/seu-usuario/subdomain-http-scanner.git
cd subdomain-http-scanner
```

### 2\. Install dependencies:

```shell
pip install dnspython requests tqdm urllib3
```

### 3\. Run the script:

```
python scanner.py -d example.com -w wordlist.txt
```

### 4\. Additional options:

```yaml
--dns-workers # Number of DNS threads (default: 50)
--http-workers # Number of HTTP threads (default: 20)
--dns-timeout # Timeout per DNS attempt in seconds (default: 1.0)
--dns-lifetime # Total time per DNS query in seconds (default: 2.0)
```

During execution, the script will ask if you want to verify the subdomains that are online, allowing you to enable HTTP/HTTPS checking.

-----

## 💡 Example Output

<img width="463" height="359" alt="image" src="https://github.com/user-attachments/assets/fd384d3d-9c7a-480c-8eda-d46a751d7b20" />
<img width="527" height="405" alt="image" src="https://github.com/user-attachments/assets/4c2befa0-8c98-44fc-a0cd-577a46ec3da3" />

-----

## ⚙️ Internal Settings

```yaml
DNS Timeout: DEFAULT_DNS_TIMEOUT = 1.0 s
DNS Lifetime: DEFAULT_DNS_LIFETIME = 2.0 s
DNS Threads: DEFAULT_MAX_WORKERS = 50
HTTP Threads: DEFAULT_HTTP_WORKERS = 20
HTTP Timeout: HTTP_TIMEOUT = 10 s
```

-----

## 📖 Topics I Studied to Build This Script

  - [dnspython](https://www.dnspython.org/)
  - [requests](https://docs.python-requests.org/)
  - [tqdm](https://tqdm.github.io/)
  - DNS Concepts: A, AAAA, MX, NS, Wildcards
  - Passive and Active Reconnaissance for Offensive Security

-----

#### I'm open to any tips or improvements!
