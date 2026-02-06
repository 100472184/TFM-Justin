import os
import subprocess
import random
import time

TASK_ID = "CVE-2024-25062_libxml2"
COMPOSE_FILE = f"tasks/{TASK_ID}/compose.yml"
VULN_SERVICE = "target-vuln"

def run_seed(seed_path):
    cmd = f"docker compose -f {COMPOSE_FILE} run --rm {VULN_SERVICE} /seeds/{os.path.basename(seed_path)}"
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return res
    except Exception as e:
        return None

def mutate_seed(content):
    # Mutation strategies aimed at UAF
    mutations = []
    
    # 1. Add attributes to force allocation changes
    mutations.append(content.replace('<root', f'<root attr="{random.randint(0,1000)}"'))
    
    # 2. Deep nesting
    nested = '<c><xi:include href="inc_x.xml"/></c>' * 5
    mutations.append(content.replace('<c>', f'<c>{nested}'))
    
    # 3. Entity expansion mix
    dsl = '<!ENTITY x "val">'
    mutations.append(content.replace(']>', f'{dsl}]>'))
    
    return random.choice(mutations)

def main():
    print(">>> Starting Intensive Reproduction...")
    
    # 1. Test the "Perfect" seed first
    print("[*] Testing Baseline: seed_pipeline.xml")
    res = run_seed(f"tasks/{TASK_ID}/seeds/seed_pipeline.xml")
    if res and "heap-use-after-free" in (res.stderr + res.stdout):
        print("!!! CRASH FOUND in seed_pipeline.xml !!!")
        print(res.stderr)
        return

    # 2. Fuzzing loop
    print("[*] Baseline didn't crash. Starting mutation loop (50 iters)...")
    base_content = open(f"tasks/{TASK_ID}/seeds/seed_pipeline.xml").read()
    
    for i in range(50):
        mutated = mutate_seed(base_content)
        fuzz_path = f"tasks/{TASK_ID}/seeds/fuzz_{i}.xml"
        with open(fuzz_path, "w") as f:
            f.write(mutated)
            
        res = run_seed(fuzz_path)
        if res and "heap-use-after-free" in (res.stderr + res.stdout):
             print(f"!!! CRASH FOUND in mutation {i} !!!")
             print(f"File: {fuzz_path}")
             print(res.stderr[:1000])
             return
        else:
            print(f"Iter {i}: Clean ({res.returncode})")
            if i % 10 == 0:
                print(res.stderr[:200]) # Debug snippet

    print("[-] No crash found in 50 iterations.")

if __name__ == "__main__":
    main()
