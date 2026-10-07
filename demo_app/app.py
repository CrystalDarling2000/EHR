"""HyL-EHR demo console.  Run:  python demo_app/app.py   then open http://127.0.0.1:8765

A small local web server (Python standard library only) in front of the same
hylehr code the experiments use. The only third-party package needed is
`cryptography`.
"""
import json
import os
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import anchoring_lab          # noqa: E402
import attacks                # noqa: E402
from world import DemoWorld   # noqa: E402

LOCK = threading.Lock()
WORLD = DemoWorld()


def handle(path, body):
    global WORLD
    if path == "/api/state":
        pass
    elif path == "/api/reset":
        WORLD = DemoWorld(int(body.get("validators", 4)))
    elif path == "/api/add_record":
        WORLD.add_record(body["rtype"])
    elif path == "/api/grant":
        WORLD.grant(body["scope"], body.get("purpose", "treatment"), int(body.get("days", 30)))
    elif path == "/api/revoke":
        WORLD.revoke()
    elif path == "/api/transfer":
        WORLD.transfer(body["rec_id"])
    elif path == "/api/emergency":
        WORLD.emergency(body["rec_id"])
    elif path == "/api/tick":
        WORLD.tick()
    elif path == "/api/prove":
        WORLD.prove(body["tx_id"])
    elif path == "/api/attacks":
        return {"cases": attacks.catalogue()}
    elif path == "/api/attack":
        return attacks.run(body["id"])
    elif path == "/api/anchoring":
        return anchoring_lab.compare(int(body.get("budget", 288)), float(body.get("critical_pct", 0.1)),
                                     float(body.get("sensitive_pct", 5.0)), float(body.get("rate", 2.0)))
    else:
        raise KeyError(path)
    return WORLD.state()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload, ctype="application/json"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "static", "index.html"), "rb") as fh:
                self._send(200, fh.read(), "text/html; charset=utf-8")
        elif self.path.startswith("/api/"):
            self._api({})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad JSON"})
        self._api(body)

    def _api(self, body):
        try:
            with LOCK:
                self._send(200, handle(self.path.split("?")[0], body))
        except KeyError as exc:
            self._send(404, {"error": f"unknown request {exc}"})
        except Exception as exc:                       # show the reason in the console UI
            self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("HYLEHR_PORT", "8765"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"HyL-EHR demo console running at {url}   (Ctrl+C to stop)")
    if "--no-browser" not in sys.argv:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
