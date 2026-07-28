"""
Run the verify API server.

Usage:
    python -m apex_psi_verify                # default port 5000
    python -m apex_psi_verify --port 8080    # custom port
    python -m apex_psi_verify --host 0.0.0.0 # bind all interfaces
"""
import argparse
import os
from pathlib import Path

from .apex_verify_api import main as api_main


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--home", default=os.environ.get(
        "APEX_PSI_HOME", str(Path.home() / ".apex-psi-verify")))
    args = p.parse_args()
    os.environ["APEX_PSI_HOME"] = args.home
    Path(args.home).mkdir(parents=True, exist_ok=True)
    print(f"APEX PSI verify API starting on http://{args.host}:{args.port}")
    print(f"  data home: {args.home}")
    api_main(host=args.host, port=args.port)
