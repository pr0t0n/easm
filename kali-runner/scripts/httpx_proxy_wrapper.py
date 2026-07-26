#!/usr/bin/env python3
"""Run ProjectDiscovery httpx, injecting an outbound proxy when configured.

Docker Desktop/VPN environments may allow host egress while blocking direct TCP
from bridge-network containers. In that case KALI_OUTBOUND_PROXY points at the
Docker Desktop proxy (for example http://192.168.65.7:3128). ProjectDiscovery
httpx does not reliably honor HTTP_PROXY/HTTPS_PROXY for probes, so the runner
must pass -proxy explicitly. In normal environments the wrapper is transparent.
"""

from __future__ import annotations

import os
import subprocess
import sys


def main() -> int:
    proxy = (
        os.getenv("KALI_OUTBOUND_PROXY")
        or os.getenv("HTTPS_PROXY")
        or os.getenv("HTTP_PROXY")
        or os.getenv("https_proxy")
        or os.getenv("http_proxy")
        or ""
    ).strip()
    argv = ["/opt/tools/bin/httpx", *sys.argv[1:]]
    if proxy and "-proxy" not in argv and "--proxy" not in argv:
        argv.extend(["-proxy", proxy])
    return subprocess.call(argv)


if __name__ == "__main__":
    raise SystemExit(main())
