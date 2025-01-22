import asyncio
import logging
from typing import Tuple
from core.custom_logger.logger import setup_logger


setup_logger()
logger = logging.getLogger(__name__)

class InstallationError(Exception):
    pass


async def run_command(cmd: list, logger: logging.Logger) -> Tuple[str, str, int]:
    """Run a command and return stdout, stderr, and return code."""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return stdout.decode(), stderr.decode(), process.returncode
    except Exception as e:
        raise InstallationError(f"Command execution failed: {str(e)}")


async def verify_rust_installation(logger: logging.Logger) -> bool:
    """Verify Rust/Cargo installation"""
    try:
        stdout, stderr, returncode = await run_command(['cargo', '--version'], logger)
        if returncode == 0:
            return True
    except FileNotFoundError:
        logger.warning("Rust/Cargo not found. Look at: https://doc.rust-lang.org/cargo/getting-started/installation.html")

    return False


async def verify_rustscan_installation(logger: logging.Logger) -> bool:
    try:
        stdout, stderr, returncode = await run_command(['rustscan', '--version'], logger)
        if returncode == 0:
            return True
    except Exception as e:
        logger.error(f"rustscan not found. Try to install it by: cargo install rustscan")
    return False


async def verify_all_installations() -> bool:
    """Verify all required installations."""

    try:
        # Verify Rust installation
        if not await verify_rust_installation(logger):
            return False

        # Verify RustScan installation
        if not await verify_rustscan_installation(logger):
            return False

        return True

    except Exception as e:
        logger.error(f"Unexpected error during installation: {str(e)}")
        return False


if __name__ == "__main__":
    asyncio.run(verify_all_installations())