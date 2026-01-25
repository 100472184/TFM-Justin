#!/usr/bin/env python3
"""
Docker readiness verification utilities.

This module provides functions to verify that Docker images are fully ready
after build. There is a timing issue where freshly built images don't respond
immediately to docker run commands - they need several attempts before the
container starts properly.
"""
from __future__ import annotations
import subprocess
import time
from pathlib import Path
from typing import Optional


def verify_image_ready(
    image_name: str,
    entrypoint: str,
    args: list[str],
    max_attempts: int = 5,
    retry_delay: float = 1.0,
    timeout: int = 10
) -> tuple[bool, Optional[str]]:
    """
    Verify that a Docker image is ready by attempting to run it until it responds.
    
    After building images, Docker needs time to initialize. This function retries
    docker run commands until the container responds with output, or max attempts
    is reached.
    
    Args:
        image_name: Full Docker image name (e.g., "cve-2024-57970_libarchive-target-vuln")
        entrypoint: Entrypoint to override (e.g., "/opt/target/bin/bsdtar")
        args: Arguments to pass to entrypoint (e.g., ["--version"])
        max_attempts: Maximum number of retry attempts (default: 5)
        retry_delay: Seconds to wait between attempts (default: 1.0)
        timeout: Timeout in seconds for each docker run (default: 10)
    
    Returns:
        Tuple of (success: bool, output: Optional[str])
        - success: True if container responded with non-empty output
        - output: The stdout from successful run, or None if failed
    
    Example:
        >>> success, output = verify_image_ready(
        ...     "cve-2024-57970_libarchive-target-vuln",
        ...     "/opt/target/bin/bsdtar",
        ...     ["--version"]
        ... )
        >>> if success:
        ...     print(f"Image ready: {output}")
    """
    for attempt in range(1, max_attempts + 1):
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", "--entrypoint", entrypoint, image_name] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            # Check if we got output (even if exit code is non-zero)
            if result.stdout.strip():
                return True, result.stdout.strip()
            
            # No output yet, wait and retry
            if attempt < max_attempts:
                time.sleep(retry_delay)
                
        except subprocess.TimeoutExpired:
            # Timeout - Docker not ready yet
            if attempt < max_attempts:
                time.sleep(retry_delay)
        except Exception as e:
            # Other error - probably Docker not running
            return False, None
    
    # Max attempts reached without success
    return False, None


def verify_task_images_ready(
    task_id: str,
    max_attempts: int = 5,
    retry_delay: float = 1.0,
    verbose: bool = True
) -> tuple[bool, dict[str, Optional[str]]]:
    """
    Verify that both vulnerable and fixed images for a task are ready.
    
    This is the main function to call after building task images. It verifies
    both the vulnerable and fixed versions respond correctly.
    
    Args:
        task_id: Task ID (e.g., "CVE-2024-57970_libarchive")
        max_attempts: Maximum retry attempts per image (default: 5)
        retry_delay: Seconds between retries (default: 1.0)
        verbose: Print progress messages (default: True)
    
    Returns:
        Tuple of (all_ready: bool, versions: dict)
        - all_ready: True if both images are ready
        - versions: Dict with keys 'vuln' and 'fixed' mapping to version strings
    
    Example:
        >>> ready, versions = verify_task_images_ready("CVE-2024-57970_libarchive")
        >>> if ready:
        ...     print(f"Vuln: {versions['vuln']}")
        ...     print(f"Fixed: {versions['fixed']}")
    """
    # Construct image names based on task_id convention
    vuln_image = f"{task_id}-target-vuln"
    fixed_image = f"{task_id}-target-fixed"
    
    # Determine entrypoint based on task (currently hardcoded for libarchive)
    # TODO: Make this configurable per task
    entrypoint = "/opt/target/bin/bsdtar"
    
    versions = {}
    
    # Verify vulnerable image
    if verbose:
        print(f"  Verifying vulnerable image ({vuln_image})...")
    
    vuln_ready, vuln_version = verify_image_ready(
        vuln_image,
        entrypoint,
        ["--version"],
        max_attempts=max_attempts,
        retry_delay=retry_delay
    )
    
    if vuln_ready:
        versions['vuln'] = vuln_version
        if verbose:
            print(f"    ✓ Vulnerable image ready: {vuln_version.split()[0:3]}")
    else:
        versions['vuln'] = None
        if verbose:
            print(f"    ✗ Vulnerable image not responding after {max_attempts} attempts")
        return False, versions
    
    # Verify fixed image
    if verbose:
        print(f"  Verifying fixed image ({fixed_image})...")
    
    fixed_ready, fixed_version = verify_image_ready(
        fixed_image,
        entrypoint,
        ["--version"],
        max_attempts=max_attempts,
        retry_delay=retry_delay
    )
    
    if fixed_ready:
        versions['fixed'] = fixed_version
        if verbose:
            print(f"    ✓ Fixed image ready: {fixed_version.split()[0:3]}")
    else:
        versions['fixed'] = None
        if verbose:
            print(f"    ✗ Fixed image not responding after {max_attempts} attempts")
        return False, versions
    
    return True, versions


def wait_for_task_images(
    task_id: str,
    max_attempts: int = 5,
    retry_delay: float = 1.0
) -> bool:
    """
    Wait for task images to be ready (blocking).
    
    Simple wrapper around verify_task_images_ready that returns only success status.
    Use this when you just need to block until images are ready.
    
    Args:
        task_id: Task ID (e.g., "CVE-2024-57970_libarchive")
        max_attempts: Maximum retry attempts per image (default: 5)
        retry_delay: Seconds between retries (default: 1.0)
    
    Returns:
        True if both images are ready, False otherwise
    """
    ready, _ = verify_task_images_ready(task_id, max_attempts, retry_delay, verbose=True)
    return ready
