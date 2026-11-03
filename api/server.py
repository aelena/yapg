"""Compatibility shim. The API now lives in `keygen.server`; run it with `keygen serve`.

    pip install -e ".[api]"      # from the repo root
    python api/server.py         # still works
"""

from keygen.server import app

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False, access_log=False, single_process=True)
