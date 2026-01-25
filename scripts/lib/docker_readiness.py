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
    max_attempts: int = 999,
    retry_delay: float = 2.0
) -> tuple[bool, Optional[str]]:
    """
    Verify that a Docker image is ready by attempting to run it until it responds.
    
    After building images, Docker needs time to initialize (~0.8-1s per attempt).
    This function retries docker run commands until the container responds with
    output. Uses the EXACT logic validated in test_docker_ready.py:
    - NO timeout on subprocess.run (let command finish naturally)
    - Wait 2 seconds between attempts (validated optimal)
    - Measure elapsed time per attempt
    - Typically succeeds by attempt 2-3
    
    Args:
        image_name: Full Docker image name (e.g., "cve-2024-57970_libarchive-target-vuln")
        entrypoint: Entrypoint to override (e.g., "/opt/target/bin/bsdtar")
        args: Arguments to pass to entrypoint (e.g., ["--version"])
        max_attempts: Maximum number of retry attempts (default: 999, effectively infinite)
        retry_delay: Seconds to wait between attempts (default: 2.0, validated optimal)
    
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
        >>> print(f"Image ready: {output}")
    """
    cmd = ["docker", "run", "--rm", "--entrypoint", entrypoint, image_name] + args
    
    attempt = 1
    while attempt <= max_attempts:
        start_time = time.time()
        
        try:
            # NO TIMEOUT - let the command finish naturally
            # This is CRITICAL - timeout was causing 58+ failed attempts
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            elapsed = time.time() - start_time
            
            # Check if we got output (even if exit code is non-zero)
            if result.stdout.strip():
                return True, result.stdout.strip()
            
            # No output yet - this is normal for first 1-2 attempts
            # Wait 2 seconds before retry (validated optimal timing)
            time.sleep(2.0)
            attempt += 1
            
        except Exception as e:
            # Other error - probably Docker not running
            return False, None
    
    # Max attempts reached without success (should never happen with max_attempts=999)
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
    # Docker image names MUST be lowercase
    vuln_image = f"{task_id.lower()}-target-vuln"
    fixed_image = f"{task_id.lower()}-target-fixed"
    
    # Determine entrypoint based on task (currently hardcoded for libarchive)
    # TODO: Make this configurable per task
    entrypoint = "/opt/target/bin/bsdtar"
    
    versions = {}
    
    # Verify vulnerable image
    if verbose:
        print(f"  Verifying vulnerable image ({vuln_image})...")
    
    attempt = 1
    while attempt <= max_attempts:
        if verbose and attempt > 1:
            print(f"    Attempt {attempt}...")
        
        vuln_ready, vuln_version = verify_image_ready(
            vuln_image,
            entrypoint,
            ["--version"],
            max_attempts=1,  # Single attempt, we control the loop
            retry_delay=retry_delay
        )
        
        if vuln_ready:
            versions['vuln'] = vuln_version
            if verbose:
                print(f"    ✓ Vulnerable image ready after {attempt} attempt(s)")
                print(f"      {vuln_version.split()[0:3]}")
            break
        else:
            if verbose:
                print(f"    ○ Attempt {attempt}: No output, waiting 2s...")
            time.sleep(2.0)
            attempt += 1
    
    if not vuln_ready:
        versions['vuln'] = None
        if verbose:
            print(f"    ✗ Vulnerable image not responding after {max_attempts} attempts")
        return False, versions
    
    # Verify fixed image
    if verbose:
        print(f"\n  Verifying fixed image ({fixed_image})...")
    
    attempt = 1
    while attempt <= max_attempts:
        if verbose and attempt > 1:
            print(f"    Attempt {attempt}...")
        
        fixed_ready, fixed_version = verify_image_ready(
            fixed_image,
            entrypoint,
            ["--version"],
            max_attempts=1,  # Single attempt, we control the loop
            retry_delay=retry_delay
        )
        
        if fixed_ready:
            versions['fixed'] = fixed_version
            if verbose:
                print(f"    ✓ Fixed image ready after {attempt} attempt(s)")
                print(f"      {fixed_version.split()[0:3]}")
            break
        else:
            if verbose:
                print(f"    ○ Attempt {attempt}: No output, waiting 2s...")
            time.sleep(2.0)
            attempt += 1
    
    if not fixed_ready:
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
