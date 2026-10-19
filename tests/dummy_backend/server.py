"""Amont factice du banc d'essai de la bordure.

Répond à toute requête par un JSON décrivant ce que la bordure lui a transmis :
chemin reçu (après réécriture), en-tête `Host` et identifiant de trace. C'est
suffisant pour prouver que l'aiguillage est correct, sans embarquer un vrai
service.

Usage : python server.py <port>
"""

from __future__ import annotations

import http.server
import json
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _repondre(self) -> None:  # noqa: N802
        charge = json.dumps(
            {
                "path": self.path,
                "host": self.headers.get("Host"),
                "trace": self.headers.get("X-Request-ID"),
                "forwarded_for": self.headers.get("X-Forwarded-For"),
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(charge)))
        self.end_headers()
        self.wfile.write(charge)

    do_GET = _repondre
    do_POST = _repondre
    do_PUT = _repondre

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Silence : le banc d'essai mesure la bordure, pas l'amont."""


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    serveur = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    serveur.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
