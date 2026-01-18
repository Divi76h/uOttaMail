import os
import socket
import time

from django.core.management.base import BaseCommand
from django.db import connections
from django.db.utils import OperationalError


def _tcp_check(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class Command(BaseCommand):
    """Wait for Postgres + Solace broker ports to be reachable.

    This prevents the Django containers from crashing on startup due to
    Compose only ordering container start, not service readiness.
    """

    help = "Wait for Postgres and Solace broker to become ready."

    def handle(self, *args, **options):
        max_tries = int(os.getenv("WAIT_MAX_TRIES", "60"))
        delay_s = float(os.getenv("WAIT_DELAY", "1"))

        # --- Postgres ---
        self.stdout.write("[wait] Waiting for Postgres...")
        for i in range(1, max_tries + 1):
            try:
                conn = connections["default"]
                conn.ensure_connection()
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                self.stdout.write(self.style.SUCCESS("[wait] Postgres ready"))
                break
            except OperationalError:
                if i == max_tries:
                    raise
                time.sleep(delay_s)

        # --- Solace MQTT port ---
        host = os.getenv("SOLACE_HOST", "broker")
        port = int(os.getenv("SOLACE_MQTT_PORT", os.getenv("SOLACE_PORT", "1883")))

        self.stdout.write(f"[wait] Waiting for Solace MQTT {host}:{port}...")
        for i in range(1, max_tries + 1):
            if _tcp_check(host, port, timeout=1.0):
                self.stdout.write(self.style.SUCCESS("[wait] Solace MQTT port reachable"))
                return
            if i == max_tries:
                raise RuntimeError(f"Solace MQTT port not reachable at {host}:{port}")
            time.sleep(delay_s)
