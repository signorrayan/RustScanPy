import asyncio
import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime
from sys import exit
from typing import List, Dict

import dns.asyncresolver

from core.custom_logger.logger import setup_logger
from core.utils import save_results
from verify_deps import verify_all_installations

setup_logger()
logger = logging.getLogger(__name__)


@dataclass
class ScanTarget:
    target: str  # Can be domain, IP, or CIDR
    resolved_ips: List[str]
    is_behind_cdn: bool
    is_ip: bool = False
    is_cidr: bool = False
    retry_count: int = 0
    max_retries: int = 3


class RustScanner:
    CDN_RANGES = [
        '103.21.244.0/22',  # Cloudflare
        '173.245.48.0/20',  # Cloudflare
        '104.16.0.0/12',  # Cloudflare
        '13.32.0.0/15',  # AWS CloudFront
        '205.251.192.0/19',  # AWS CloudFront
    ]

    def __init__(
            self,
            batch_size: int = 30000,
            ulimit: int = 45000,
            timeout: int = 3500,
            concurrent_limit: int = 5,
            tries: int = 1,
            service_detection: bool = True,
            retry_delay: int = 30,
    ):
        self.batch_size = batch_size
        self.ulimit = ulimit
        self.timeout = timeout
        self.concurrent_limit = concurrent_limit
        self.tries = tries
        self.service_detection = service_detection
        self.retry_delay = retry_delay
        self.semaphore = asyncio.Semaphore(concurrent_limit)
        self._cdn_networks = [ipaddress.ip_network(cidr) for cidr in self.CDN_RANGES]

    async def _is_valid_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    async def _is_valid_cidr(self, cidr: str) -> bool:
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    async def _expand_cidr(self, cidr: str) -> List[str]:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            logger.error(f"Invalid CIDR notation: {cidr}, Error: {str(e)}")
            return []

    async def _is_ip_behind_cdn(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in network for network in self._cdn_networks)
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False

    async def _resolve_target(self, target: str) -> ScanTarget:
        if await self._is_valid_ip(target):
            return ScanTarget(
                target=target,
                resolved_ips=[target],
                is_behind_cdn=await self._is_ip_behind_cdn(target),
                is_ip=True
            )
        elif await self._is_valid_cidr(target):
            ips = await self._expand_cidr(target)
            return ScanTarget(
                target=target,
                resolved_ips=ips,
                is_behind_cdn=False,
                is_cidr=True
            )
        else:
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5

                answers = await resolver.resolve(target, 'A')
                ips = [str(rdata) for rdata in answers]

                is_behind_cdn = False
                for ip in ips:
                    if await self._is_ip_behind_cdn(ip):
                        is_behind_cdn = True
                        logger.warning(f"Domain {target} appears to be behind a CDN (IP: {ip})")
                        break

                return ScanTarget(
                    target=target,
                    resolved_ips=ips,
                    is_behind_cdn=is_behind_cdn
                )
            except Exception as e:
                logger.error(f"Error resolving target {target}: {str(e)}")
                return ScanTarget(
                    target=target,
                    resolved_ips=[],
                    is_behind_cdn=False
                )

    async def _process_discovered_port(self, line: str, scan_results: Dict) -> None:
        """Process a line containing discovered port information."""
        try:
            parts = line.split()
            port = int(parts[3].split('/')[0])
            ip = parts[5]

            if ip not in scan_results["ip_results"]:
                scan_results["ip_results"][ip] = {
                    "ports": []
                }

            port_entry = {
                "port": port,
                "state": "open",
                "protocol": "tcp",
                "service": None,
                "version": None
            }
            scan_results["ip_results"][ip]["ports"].append(port_entry)
            logger.info(line)
        except (IndexError, ValueError) as e:
            logger.error(f"Error parsing Discovered line: {line}. {e}")

    async def _process_service_info(self, line: str, current_ip: str, scan_results: Dict) -> None:
        """Process a line containing service information on a port."""
        try:
            parts = line.strip().split()
            if len(parts) >= 3:
                port = int(parts[0].split('/')[0])
                service = parts[2]

                # Find the IP from scan results that has this port
                for ip, ip_data in scan_results["ip_results"].items():
                    for port_entry in ip_data["ports"]:
                        if port_entry["port"] == port:
                            port_entry["service"] = service
                            if len(parts) > 3:
                                # Get all parts after service name except 'syn-ack'
                                version_parts = [p for p in parts[3:] if p != "syn-ack"]
                                if version_parts:
                                    port_entry["version"] = " ".join(version_parts)
                            logger.info(f"Updated service information for {ip}:{port} - {service}")
                            break
        except (IndexError, ValueError) as e:
            logger.error(f"Error parsing service line: {line}. {e}")

    async def setup_base_command(self, target: ScanTarget) -> List[str]:
        base_cmd = [
            "rustscan",
            "-a", target.target,
            "-b", str(self.batch_size),
            "--ulimit", str(self.ulimit),
            "-t", str(self.timeout),
            "--tries", str(self.tries),
            "--accessible"
        ]

        if self.service_detection:
            base_cmd.extend(["--", "-Sv", "-T4", "-n"])  # Nmap flags -> -Pn: No ping, -T4: Aggressive timing template.

        return base_cmd

    async def _execute_rustscan(self, target: ScanTarget) -> Dict:
        async with self.semaphore:
            try:
                logger.info(f"Starting scan for {target.target}")

                scan_results = {
                    "ip_results": {},
                    "warnings": [],
                    "errors": []
                }

                base_cmd = await self.setup_base_command(target)

                process = await asyncio.create_subprocess_exec(
                    *base_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                current_ip = None

                async def handle_output(stream, is_error=False):
                    nonlocal current_ip
                    while True:
                        line = await stream.readline()
                        if not line:
                            break
                        line_str = line.decode().strip()

                        if is_error:
                            if line_str not in scan_results["errors"]:
                                scan_results["errors"].append(line_str)
                                logger.error(f"RustScan Error: {line_str}")
                        else:
                            if "Scanning" in line_str:
                                try:
                                    # Extract IP from line
                                    start = line_str.find("(") + 1
                                    end = line_str.find(")")
                                    if start > 0 and end > start:
                                        current_ip = line_str[start:end]
                                except Exception as e:
                                    logger.error(f"Error extracting IP from line: {line_str}. {e}")
                            elif "Discovered open port" in line_str:
                                await self._process_discovered_port(line_str, scan_results)
                            elif "/tcp" in line_str and "open" in line_str and "Discovered" not in line_str:
                                await self._process_service_info(line_str, current_ip, scan_results)
                            elif "Warning: " in line_str:
                                scan_results["warnings"].append(line_str)

                await asyncio.gather(
                    handle_output(process.stdout),
                    handle_output(process.stderr, is_error=True)
                )

                exit_code = await process.wait()

                return {
                    "timestamp": datetime.now().isoformat(),
                    "target": target.target,
                    "is_ip": target.is_ip,
                    "is_cidr": target.is_cidr,
                    "is_behind_cdn": target.is_behind_cdn,
                    "scan_results": scan_results,
                    "status": "completed",
                    "exit_code": exit_code
                }

            except Exception as e:
                logger.error(f"Error scanning {target.target}: {str(e)}")
                if target.retry_count < target.max_retries:
                    target.retry_count += 1
                    logger.info(
                        f"Retrying scan for {target.target} (Attempt {target.retry_count}/{target.max_retries})")
                    await asyncio.sleep(self.retry_delay)
                    return await self._execute_rustscan(target)
                return {
                    "target": target.target,
                    "error": str(e),
                    "status": "failed"
                }

    async def scan_target(self, target: str) -> Dict:
        resolved = await self._resolve_target(target)
        if not resolved.resolved_ips:
            return {"target": target, "error": "Target resolution failed"}
        return await self._execute_rustscan(resolved)

    async def bulk_scan(self, targets: List[str]) -> List[Dict]:
        if not await verify_all_installations():
            return [{
                "error": "Required tools (Rust/Cargo/RustScan) are not installed",
                "status": "failed",
                "targets": targets
            }]

        tasks = []
        for target in targets:
            tasks.append(self.scan_target(target))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                processed_results.append({
                    "error": str(result),
                    "status": "failed",
                    "type": result.__class__.__name__
                })
            else:
                processed_results.append(result)

        return processed_results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Async RustScan Scanner")
    parser.add_argument("targets", nargs="+", help="Domains, IPs, or CIDR ranges to scan")
    parser.add_argument("-b", "--batch-size", type=int, default=30000)
    parser.add_argument("-u", "--ulimit", type=int, default=45000)
    parser.add_argument("-t", "--timeout", type=int, default=2500)
    parser.add_argument("-c", "--concurrent", type=int, default=5)
    parser.add_argument("--tries", type=int, default=1)
    parser.add_argument("-nsd", "--no-service-detection", action="store_true")
    parser.add_argument("-o", "--output")

    args = parser.parse_args()

    rust_scanner = RustScanner(
        batch_size=args.batch_size,
        ulimit=args.ulimit,
        timeout=args.timeout,
        concurrent_limit=args.concurrent,
        tries=args.tries,
        service_detection=not args.no_service_detection
    )

    asyncio.run(run(rust_scanner, args.targets, args.output))


async def run(rust_scanner, targets, output):
    try:
        results = await rust_scanner.bulk_scan(targets)
        await save_results(results, output)
    except Exception as e:
        logger.error(f"Error during scan execution: {str(e)}")
        exit(1)


if __name__ == "__main__":
    main()
