



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
python3 rustpy.py 192.168.1.0/29 -b 20000 -u 45000 -t 4000 -c 3
```

- For mixed targets:
```
python3 rustpy.py 192.168.10.146 example.com
```

As a library:
```python
import rustpy

rust_scanner = rustpy.RustScanner(
    batch_size=batch_size, # By default it is 30000
    ulimit=ulimit, # By default it is 45000
    timeout=timeout, # By default it is 3500
    concurrent_limit=concurrent, # By default it is 5
    tries=tries, # By default it is 1
    service_detection=False, # setting it to True will enable deeper service detection, but consuming more time.
)

await rustpy.run(rust_scanner, targets, output))