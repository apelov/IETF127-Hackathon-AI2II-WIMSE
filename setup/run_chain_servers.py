"""Start Maurice (:5050) + Domain A (:5051) + Domain B (:5060..5063) + P2/P7/P8 Executor (:5064)."""
import os
import pathlib
import signal
import subprocess
import sys
import time

root = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "peers"))

import domain_a  # noqa: E402
import domain_b  # noqa: E402
import p2_p7_p8_executor  # noqa: E402


def main():
    srv_a = domain_a.start_in_thread(5051)
    srvs_b = domain_b.start_all_in_threads()
    srv_p = p2_p7_p8_executor.start_in_thread(5064)

    binary = root / "bin/maurice"
    config = pathlib.Path.home() / ".maurice/one/config/standalone.yaml"
    proc = None
    srv_fallback = None

    if binary.is_file() and config.is_file():
        proc = subprocess.Popen([str(binary), "serve", "--runtime-config", str(config)])
    else:
        srv_fallback = domain_a.start_maurice_fallback_on_5050(5050)

    def _stop(signum, frame):
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if srv_fallback is not None:
            srv_fallback.shutdown()
        srv_p.shutdown()
        domain_b.shutdown_all(srvs_b)
        srv_a.shutdown()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    if proc is not None:
        raise SystemExit(proc.wait())
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
