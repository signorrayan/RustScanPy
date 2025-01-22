



### Installation:
- Install nmap from https://nmap.org/download.html (`sudo apt install nmap` on Debian based systems)
- Install Cargo from https://doc.rust-lang.org/cargo/getting-started/installation.html
- Install rustscan by running `cargo install rustscan`


### Usage:
- For a single IP:
```
python3 rustpy.py <IP> -b 5000 -t 2000 -c 3
```

- For a domain:
```
python3 rustpy.py example.com
```

- For a CIDR range (use a small range for testing):
```
python3 rustpy.py 192.168.1.0/29 -b 5000 -t 2000 -c 3
```

- For mixed targets:
```
python3 rustpy.py 45.77.227.31 example.com 192.168.1.0/29 -b 5000 -t 2000 -c 3
```

As a library:
```python
import rustpy

rust_scanner = rustpy.RustScanner(
    batch_size=args.batch_size,
    ulimit=args.ulimit,
    timeout=args.timeout,
    concurrent_limit=args.concurrent,
    tries=args.tries,
    rate=args.rate,
    greppable=args.greppable,
    service_detection=not args.no_service_detection
)

await rustpy.run(rust_scanner, targets, output))