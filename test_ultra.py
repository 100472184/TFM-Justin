import subprocess
import time

print("Starting 100-run stress test with seed_ultra_massive.xml...")
for i in range(100):
    result = subprocess.run([
        "docker", "compose", "-f", "tasks/CVE-2023-29469_libxml2/compose.yml",
        "run", "--rm", "target-vuln",
        "/harness/harness", "/seeds/seed_ultra_massive.xml"
    ], capture_output=True, text=True)
    
    # Check for ASan error or SIGSEGV/SIGABRT (139/134)
    if "AddressSanitizer" in result.stderr or result.returncode in [139, 134]:
        print(f"\n[CRASH DETECTED] Run {i+1}:")
        print(result.stderr[:1000]) # Print first 1000 chars of stderr
        break
    else:
        # Print progress on same line
        print(f"Run {i+1}: clean", end='\r', flush=True)

else:
    print("\nNo crash in 100 runs")
