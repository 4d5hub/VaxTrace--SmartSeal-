import argparse
import importlib.util
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integration.stack import Stack
from web3 import EthereumTesterProvider
import uvicorn

LOCK = threading.RLock()


class LockedProvider(EthereumTesterProvider):

    def make_request(self, method, params):
        with LOCK:
            return super().make_request(method, params)


def serve(app, port):
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(cfg)
    threading.Thread(target=srv.run, daemon=True).start()
    return srv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway-port", type=int, default=8000)
    ap.add_argument("--verifier-port", type=int, default=8100)
    ap.add_argument("--seed", action="store_true", help="also create and fill a demo shipment")
    a = ap.parse_args()
    stack = Stack(provider=LockedProvider(), real_clock=True, verifier_url=f"http://127.0.0.1:{a.verifier_port}")
    spec = importlib.util.spec_from_file_location("verifier_service_app", ROOT / "verifier" / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    vapp = mod.create_app(reader=stack.reader, ledger=stack.real, results_path=stack.tmp / "verifier_results.json")
    serve(stack.app, a.gateway_port)
    serve(vapp, a.verifier_port)
    if a.seed:
        stack.normal()
    print(f"""
SmartSeal stack running on an IN-PROCESS EVM chain (real contracts, no validator network).
  gateway   http://127.0.0.1:{a.gateway_port}    docs: /docs
  verifier  http://127.0.0.1:{a.verifier_port}
  API key   stack-key      (type it into the dashboard's API key box)
  dashboard dashboard\\index.html  -> "Real backend"
Seal SEAL-A1 / shipment SHP-001 {'is seeded' if a.seed else 'are not created yet: run  python integration\\\\live_demo.py seed --shipment SHP-001 --seal SEAL-A1 --key stack-key'}.
Ctrl+C to stop.""")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
