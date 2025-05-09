#!/usr/bin/env python3
import asyncio
import ssl
import socket
import argparse
import time

# Default timeout for connection attempts
DEFAULT_TIMEOUT = 5.0

async def detect_socks5(host, port, timeout):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout
        )
        writer.write(b"\x05\x01\x00")  # VER=5, NMETHODS=1, METHOD=0(no auth)
        await writer.drain()
        data = await asyncio.wait_for(reader.readexactly(2), timeout)
        writer.close()
        await writer.wait_closed()
        return data == b"\x05\x00"
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False
    except Exception:
        return False

async def detect_socks4(host, port, timeout):
    try:
        # First check if the host is an IP address or needs to be resolved
        try:
            dst_ip = socket.inet_aton(host)  # Will only work if host is a valid IPv4 address
        except socket.error:
            try:
                # Try to resolve hostname to IP
                addr_info = await asyncio.get_event_loop().getaddrinfo(host, port, socket.AF_INET)
                dst_ip = socket.inet_aton(addr_info[0][4][0])
            except (socket.error, IndexError):
                return False  # Can't resolve or invalid address

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout
        )
        dst_port = (80).to_bytes(2, 'big')
        pkt = b"\x04\x01" + dst_port + dst_ip + b"\x00"
        writer.write(pkt)
        await writer.drain()
        data = await asyncio.wait_for(reader.readexactly(8), timeout)
        writer.close()
        await writer.wait_closed()
        # VN=0x00, CD in {0x5A..0x5D}
        return data[0] == 0x00 and data[1] in (0x5A, 0x5B, 0x5C, 0x5D)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, IndexError):
        return False
    except Exception:
        return False

async def detect_http_proxy(host, port, timeout):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout
        )
        req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout)
        writer.close()
        await writer.wait_closed()
        s = data.decode('latin1', errors='ignore')
        if s.startswith("HTTP/"):
            code = int(s.split()[1])
            return 200 <= code < 300 or code == 407
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ValueError, IndexError):
        return False
    except Exception:
        return False
    return False

async def detect_http_server(host, port, timeout):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout
        )
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout)
        writer.close()
        await writer.wait_closed()
        response = data.decode('latin1', errors='ignore')

        # Check if this is a proper HTTP response
        return response.startswith("HTTP/")
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False
    except Exception:
        return False

async def detect_tls(host, port, timeout):
    """
    Returns (bool, list_of_sni_or_None)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers('DEFAULT@SECLEVEL=1')

    # Use host as SNI if it's a hostname
    sni_name = host if not host.replace('.', '').isdigit() else None

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni_name),
            timeout
        )
        ssl_obj = writer.get_extra_info('ssl_object')
        cert = ssl_obj.getpeercert()
        writer.close()
        await writer.wait_closed()

        if not cert:
            return True, None

        # Collect all DNS names from SAN
        names = []
        for typ, val in cert.get('subjectAltName', ()):
            if typ == 'DNS':
                names.append(val)

        # Fallback: also pull any Common Name entries
        for rdn in cert.get('subject', ()):
            for key, val in rdn:
                if key.lower() == 'commonname':
                    names.append(val)

        # Deduplicate while preserving order
        seen = set()
        unique_names = []
        for n in names:
            if n not in seen:
                seen.add(n)
                unique_names.append(n)

        return True, unique_names if unique_names else None

    except (asyncio.TimeoutError, ConnectionRefusedError, ssl.SSLError, OSError):
        return False, None
    except Exception:
        return False, None


async def scan_port(host, port, timeout, debug=False):
    if debug:
        print(f"Scanning {host}:{port}...")

    tasks = {
        'socks5': asyncio.create_task(detect_socks5(host, port, timeout)),
        'socks4': asyncio.create_task(detect_socks4(host, port, timeout)),
        'http_proxy': asyncio.create_task(detect_http_proxy(host, port, timeout)),
        'http': asyncio.create_task(detect_http_server(host, port, timeout)),
        'tls': asyncio.create_task(detect_tls(host, port, timeout)),
    }

    await asyncio.gather(*tasks.values())

    if debug:
        print(f"\nDetection Results for {host}:{port}:")
        print(f"- SOCKS5: {tasks['socks5'].result()}")
        print(f"- SOCKS4: {tasks['socks4'].result()}")
        print(f"- HTTP Proxy: {tasks['http_proxy'].result()}")
        print(f"- HTTP: {tasks['http'].result()}")
        tls_ok, tls_sni = tasks['tls'].result()
        print(f"- TLS: {tls_ok}, SNI(s): {tls_sni}")
        print()

    found = []
    if tasks['socks5'].result():
        found.append('socks5')
    if tasks['socks4'].result():
        found.append('socks4')
    if tasks['http_proxy'].result():
        found.append('http_proxy')

    is_http = tasks['http'].result()
    tls_ok, tls_sni = tasks['tls'].result()

    if tls_ok:
        if tls_sni:
            # show all SNI values in parentheses
            sni_list = ",".join(tls_sni)
            found.append(f"tls({sni_list})")
        else:
            found.append("tls")

    if is_http:
        if tls_ok:
            found.append("https")
        found.append("http")

    return (port, found) if found else (port, None)


async def scan_port_range(host, start_port, end_port, batch_size, timeout, debug):
    """Scan a range of ports on the host"""
    port_batches = []
    for i in range(start_port, end_port + 1, batch_size):
        batch_end = min(i + batch_size - 1, end_port)
        port_batches.append((i, batch_end))

    for start, end in port_batches:
        if debug:
            print(f"Scanning ports {start}-{end} on {host}...")

        # Create tasks for each port in the batch
        tasks = []
        for port in range(start, end + 1):
            tasks.append(scan_port(host, port, timeout, debug))

        # Run all port scans in the batch concurrently
        results = await asyncio.gather(*tasks)

        # Process and print results
        for port, protocols in results:
            if protocols:
                print(f"True {port} {' '.join(protocols)}")

async def main():
    parser = argparse.ArgumentParser(description='Port scanner with protocol detection')
    parser.add_argument('host', help='Target host to scan')
    parser.add_argument('-p', '--ports', help='Port range to scan (e.g., 1-1000 or 80,443,8080)', default='1-1000')
    parser.add_argument('-b', '--batch-size', type=int, help='Number of ports to scan per batch', default=1000)
    parser.add_argument('-t', '--timeout', type=float, help='Connection timeout in seconds', default=DEFAULT_TIMEOUT)
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args()

    host = args.host
    timeout = args.timeout
    batch_size = args.batch_size
    debug = args.debug

    # Parse port range
    try:
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
        elif ',' in args.ports:
            ports = list(map(int, args.ports.split(',')))
            start_port, end_port = min(ports), max(ports)
            # TODO: Handle non-continuous port ranges
        else:
            start_port = end_port = int(args.ports)
    except ValueError:
        print("Error: Invalid port range format. Use '1-1000' or '80,443,8080'")
        return

    # Validate port range
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Error: Port range must be between 1 and 65535, and start must be <= end")
        return

    start_time = time.time()

    await scan_port_range(host, start_port, end_port, batch_size, timeout, debug)

    if debug:
        elapsed = time.time() - start_time
        print(f"\nScan completed in {elapsed:.2f} seconds")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan aborted by user")