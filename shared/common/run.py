"""Starts the current service: `python -m common.run`.

With TLS enabled the service only accepts connections that present a client certificate
signed by the project CA (mutual TLS), so only Nginx and the other services can connect.
"""
import ssl

import uvicorn

from common.settings import get_settings


def main() -> None:
    s = get_settings()
    options: dict = {
        "host": "0.0.0.0",  # nosec B104 - container port; reachable only via internal networks + mTLS
        "port": s.port,
        "proxy_headers": True,
        "server_header": False,
    }
    if s.tls_enabled:
        tls = s.keys_dir / "tls"
        options.update(
            ssl_certfile=str(tls / "service.crt"),
            ssl_keyfile=str(tls / "service.key"),
            ssl_ca_certs=str(tls / "ca.crt"),
            ssl_cert_reqs=ssl.CERT_REQUIRED,
        )
    uvicorn.run("app.main:app", **options)


if __name__ == "__main__":
    main()
