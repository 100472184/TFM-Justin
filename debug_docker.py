import subprocess
from pathlib import Path
import uuid

tdir = Path('tasks/CVE-2024-57970_libarchive')
seed = Path('heap_of.tar')
service = 'target-vuln'
container_name = f"{service}-{uuid.uuid4().hex[:8]}"

print(f"Container name: {container_name}")
print(f"Starting container...")

# Try docker compose run directly
result = subprocess.run(
    ["docker", "compose", "-f", str(tdir / "compose.yml"), "run", "-d", "--name", container_name,
     "-v", f"{seed.resolve()}:/input/seed.bin:ro", service],
    capture_output=True,
    text=True,
    check=False
)

print(f"\nCompose run result:")
print(f"  exit_code: {result.returncode}")
print(f"  stdout: {result.stdout}")
print(f"  stderr: {result.stderr}")

# Check if container exists
check_result = subprocess.run(
    ["docker", "ps", "-a", "--filter", f"name={container_name}", "--format", "{{.Names}}"],
    capture_output=True,
    text=True
)
print(f"\nContainer exists: {container_name in check_result.stdout}")

if container_name in check_result.stdout:
    # Wait for it
    wait_result = subprocess.run(
        ["docker", "wait", container_name],
        capture_output=True,
        text=True
    )
    print(f"\nWait exit code: {wait_result.stdout.strip()}")
    
    # Get logs
    logs_result = subprocess.run(
        ["docker", "logs", container_name],
        capture_output=True,
        text=True
    )
    print(f"\nLogs stdout ({len(logs_result.stdout)} chars):")
    print(logs_result.stdout[:500])
    print(f"\nLogs stderr ({len(logs_result.stderr)} chars):")
    print(logs_result.stderr[:500])
    
    # Remove
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
