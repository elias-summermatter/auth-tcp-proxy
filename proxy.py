import asyncio
import logging
import threading
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)

DEFAULT_DURATION = 3600
MAX_DURATION = 8 * 3600
EXTEND_STEP = 3600
BUFFER_SIZE = 65536


@dataclass
class Service:
    name: str
    listen_host: str
    listen_port: int
    target_host: str
    target_port: int


def _parse_hostport(s: str) -> tuple[str, int]:
    host, port = s.rsplit(":", 1)
    return host, int(port)


class ProxyManager:
    def __init__(self, services_cfg: list[dict], audit=None):
        self.services: dict[str, Service] = {}
        for svc in services_cfg:
            lh, lp = _parse_hostport(svc["listen"])
            th, tp = _parse_hostport(svc["target"])
            self.services[svc["name"]] = Service(svc["name"], lh, lp, th, tp)

        # grant record: {"expires_at": float, "user": str | None}
        self._grants: dict[str, dict[str, dict]] = {n: {} for n in self.services}
        # Grants are mutated by Flask threads and read by the asyncio loop thread;
        # a plain lock is enough since we only do short O(1) ops inside it.
        self._lock = threading.Lock()
        self._audit = audit
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._started = threading.Event()

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._loop_thread = threading.Thread(target=self._run_loop, daemon=True, name="proxy-loop")
        self._loop_thread.start()
        self._started.wait()

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.create_task(self._serve_all())
        self._started.set()
        self._loop.run_forever()

    async def _serve_all(self) -> None:
        for svc in self.services.values():
            try:
                server = await asyncio.start_server(
                    lambda r, w, s=svc: self._handle_client(r, w, s),
                    host=svc.listen_host,
                    port=svc.listen_port,
                    reuse_address=True,
                )
                for sock in server.sockets or []:
                    log.info(
                        "listen %s on %s → %s:%d",
                        svc.name, sock.getsockname(), svc.target_host, svc.target_port,
                    )
            except OSError as e:
                log.error("bind failed for %s on %s:%d — %s",
                          svc.name, svc.listen_host, svc.listen_port, e)

    # --- connection handling ----------------------------------------------

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        svc: Service,
    ) -> None:
        peer = client_writer.get_extra_info("peername")
        ip = peer[0] if peer else "?"

        if not self._is_allowed(svc.name, ip):
            log.info("reject %s from %s (not whitelisted)", svc.name, ip)
            if self._audit:
                self._audit.record("connection_rejected", ip=ip, service=svc.name)
            client_writer.close()
            try:
                await client_writer.wait_closed()
            except Exception:
                pass
            return

        # Snapshot the granting user at accept time so we attribute the session
        # even if the grant expires or gets overwritten while the stream is open.
        granted_by = self.granting_user(svc.name, ip)

        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(svc.target_host, svc.target_port),
                timeout=10,
            )
        except Exception as e:
            log.warning("target connect failed for %s from %s: %s", svc.name, ip, e)
            if self._audit:
                self._audit.record("connection_error", ip=ip, service=svc.name,
                                   granted_by=granted_by, error=str(e))
            client_writer.close()
            try:
                await client_writer.wait_closed()
            except Exception:
                pass
            return

        log.info("open %s %s (granted_by=%s) ↔ %s:%d",
                 svc.name, ip, granted_by, svc.target_host, svc.target_port)
        if self._audit:
            self._audit.record("connection_opened", ip=ip, service=svc.name,
                               granted_by=granted_by)
        await asyncio.gather(
            self._pipe(client_reader, target_writer),
            self._pipe(target_reader, client_writer),
            return_exceptions=True,
        )
        for w in (client_writer, target_writer):
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass
        log.info("close %s %s", svc.name, ip)
        if self._audit:
            self._audit.record("connection_closed", ip=ip, service=svc.name,
                               granted_by=granted_by)

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await reader.read(BUFFER_SIZE)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.write_eof()
            except Exception:
                pass

    # --- grant management (called from Flask threads) ---------------------

    def _is_allowed(self, service_name: str, ip: str) -> bool:
        now = time.time()
        with self._lock:
            grants = self._grants.get(service_name)
            if grants is None:
                return False
            g = grants.get(ip)
            if g is None:
                return False
            if g["expires_at"] <= now:
                del grants[ip]
                return False
            return True

    def granting_user(self, service_name: str, ip: str) -> str | None:
        now = time.time()
        with self._lock:
            g = self._grants.get(service_name, {}).get(ip)
            if g is None or g["expires_at"] <= now:
                return None
            return g.get("user")

    def activate(self, service_name: str, ip: str, user: str | None = None) -> float:
        now = time.time()
        with self._lock:
            expiry = now + DEFAULT_DURATION
            self._grants[service_name][ip] = {"expires_at": expiry, "user": user}
            return expiry

    def extend(self, service_name: str, ip: str, user: str | None = None) -> float:
        now = time.time()
        with self._lock:
            grants = self._grants[service_name]
            g = grants.get(ip)
            if g is None or g["expires_at"] <= now:
                expiry = now + DEFAULT_DURATION
            else:
                expiry = min(g["expires_at"] + EXTEND_STEP, now + MAX_DURATION)
            grants[ip] = {"expires_at": expiry, "user": user}
            return expiry

    def deactivate(self, service_name: str, ip: str) -> None:
        with self._lock:
            self._grants[service_name].pop(ip, None)

    def status_for_ip(self, ip: str) -> dict[str, float]:
        now = time.time()
        out: dict[str, float] = {}
        with self._lock:
            for name, grants in self._grants.items():
                g = grants.get(ip)
                if g and g["expires_at"] > now:
                    out[name] = g["expires_at"]
        return out
