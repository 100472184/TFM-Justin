#!/usr/bin/env python3
"""
Test script to verify Docker image readiness with proper timing.

This script tests ONLY the version check command and waits appropriately
between attempts. Use this to debug Docker startup timing.

Usage:
    python test_docker_ready.py
"""
import subprocess
import sys
import time
from datetime import datetime


def print_timestamp(msg):
    """Print message with timestamp."""
    now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{now}] {msg}")


def test_image_ready():
    """Test if Docker image responds to version check."""
    image = "cve-2024-57970_libarchive-target-vuln"
    cmd = ["docker", "run", "--rm", "--entrypoint", "/opt/target/bin/bsdtar", image, "--version"]
    
    print(f"\n{'='*70}")
    print(f"Testing Docker Image Readiness")
    print(f"{'='*70}\n")
    print(f"Command: {' '.join(cmd)}\n")
    print(f"This test will:")
    print(f"  1. Run the command WITHOUT timeout (let it finish naturally)")
    print(f"  2. Wait for command to complete (may take 5-30 seconds)")
    print(f"  3. Show exact timing for each attempt")
    print(f"  4. Wait 2 seconds between attempts")
    print(f"  5. Continue until success or Ctrl+C\n")
    print(f"{'='*70}\n")
    
    attempt = 1
    while True:
        print_timestamp(f"Attempt {attempt}: Starting command...")
        start_time = time.time()
        
        try:
            # NO TIMEOUT - let the command finish naturally
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            elapsed = time.time() - start_time
            
            # Check if we got output
            if result.stdout.strip():
                print_timestamp(f"Attempt {attempt}: ✓ SUCCESS after {elapsed:.2f}s")
                print(f"\nOutput:")
                print(f"  {result.stdout.strip()}\n")
                print(f"{'='*70}")
                print(f"Image is READY after {attempt} attempt(s)")
                print(f"{'='*70}\n")
                return True
            else:
                print_timestamp(f"Attempt {attempt}: ○ No output after {elapsed:.2f}s")
                
                # Show stderr if present (might have errors)
                if result.stderr.strip():
                    print(f"  stderr: {result.stderr.strip()[:100]}")
                
                # Wait before next attempt
                print_timestamp(f"  Waiting 2 seconds before next attempt...")
                time.sleep(2.0)
                attempt += 1
                
        except KeyboardInterrupt:
            print(f"\n\n{'='*70}")
            print("Cancelled by user")
            print(f"{'='*70}\n")
            print(f"Summary:")
            print(f"  - Completed {attempt - 1} full attempts")
            print(f"  - Image did NOT respond with version")
            print(f"\nPossible issues:")
            print(f"  - Docker Desktop not running properly")
            print(f"  - Image not built correctly")
            print(f"  - WSL2 backend issues (Windows)")
            print(f"\nManual test:")
            print(f"  {' '.join(cmd)}")
            print()
            sys.exit(1)
            
        except Exception as e:
            elapsed = time.time() - start_time
            print_timestamp(f"Attempt {attempt}: ✗ ERROR after {elapsed:.2f}s")
            print(f"  Error: {e}")
            print(f"\n{'='*70}")
            print(f"Fatal error - cannot continue")
            print(f"{'='*70}\n")
            return False


if __name__ == "__main__":
    print(f"\n{'='*70}")
    print(f"Docker Image Readiness Test")
    print(f"{'='*70}\n")
    
    # Check if Docker is running
    print("Checking if Docker is running...")
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
            check=False
        )
        if result.returncode != 0:
            print("✗ Docker is not running or not accessible")
            print("\nPlease start Docker Desktop and try again.")
            sys.exit(1)
        print("✓ Docker is running\n")
    except Exception as e:
        print(f"✗ Cannot access Docker: {e}")
        print("\nPlease start Docker Desktop and try again.")
        sys.exit(1)
    
    # Check if image exists
    image = "cve-2024-57970_libarchive-target-vuln"
    print(f"Checking if image exists: {image}")
    try:
        result = subprocess.run(
            ["docker", "images", "-q", image],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        if not result.stdout.strip():
            print(f"✗ Image not found: {image}")
            print(f"\nPlease build the image first:")
            print(f"  python -m scripts.bench build CVE-2024-57970_libarchive")
            sys.exit(1)
        print(f"✓ Image exists\n")
    except Exception as e:
        print(f"✗ Cannot check image: {e}")
        sys.exit(1)
    
    # Run the test
    success = test_image_ready()
    
    if success:
        print("Test completed successfully!")
        sys.exit(0)
    else:
        print("Test failed!")
        sys.exit(1)
