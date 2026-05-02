from __future__ import annotations

import uvicorn

from .config import Settings


def main() -> None:
    settings = Settings.from_env()
    host, _, port = settings.bind.partition(":")
    uvicorn.run(
        "kbeam_auth_gateway.app:app",
        host=host or "127.0.0.1",
        port=int(port or "18090"),
        reload=False,
    )


if __name__ == "__main__":
    main()

