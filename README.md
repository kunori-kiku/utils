# Utils
**A utility repository by kunori-kiku**

---

## Table of content
- [Utils](#utils)
  - [Table of content](#table-of-content)
  - [Port scanner](#port-scanner)
    - [Options:](#options)
    - [Examples:](#examples)

---
## Port scanner
**Useful to prevent from unwanted services exposing on machines' public port**

It can be used to scan a range of ports to see if there is any **tls/http proxy/socks proxy** running on that port, making it easier to comply with the network regulations in China when co-renting China's domestic machines.

**Usage**:

To use the port scanner, run the script with the following options:

```bash
python port_scan.py <host> [options]
```

### Options:
- `<host>`: The target host to scan (e.g., `127.0.0.1` or `example.com`).
- `-p, --ports`: Port range to scan (e.g., `1-1000` or `80,443,8080`). Default is `1-1000`.
- `-b, --batch-size`: Number of ports to scan per batch. Default is `1000`.
- `-t, --timeout`: Connection timeout in seconds. Default is `5.0`.
- `-d, --debug`: Enable debug output for detailed information.

### Examples:
1. Scan ports 1 to 1000 on `127.0.0.1`:
   ```bash
   python port_scan.py 127.0.0.1
   ```

2. Scan specific ports `80`, `443`, and `8080` on `example.com`:
   ```bash
   python port_scan.py example.com -p 80,443,8080
   ```

3. Scan ports 1 to 5000 with a timeout of 10 seconds:
   ```bash
   python port_scan.py 192.168.1.1 -p 1-5000 -t 10
   ```

4. Enable debug mode for detailed output:
   ```bash
   python port_scan.py localhost -d
   ```
