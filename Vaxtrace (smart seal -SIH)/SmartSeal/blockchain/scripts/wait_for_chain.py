import json
import sys
import time
import urllib.request

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8545"


def block():
    req = urllib.request.Request(URL, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}).encode(),
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=3) as r:
        return int(json.load(r)["result"], 16)


deadline, first = time.time() + 150, None
while time.time() < deadline:
    try:
        b = block()
        first = b if first is None else first
        if b > first:
            print(f"chain is sealing blocks (block {b})")
            sys.exit(0)
    except Exception:
        pass
    time.sleep(2)
print("timed out: no blocks produced. Check `docker compose logs node1` (see README troubleshooting).")
sys.exit(1)
