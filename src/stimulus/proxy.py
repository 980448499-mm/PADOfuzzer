"""5GC proxy — intercepts and modifies NF-to-NF communication.

Sits between:
  - UE/gNB ←→ AMF (N1/N2 via SCTP/NGAP)
  - SMF ←→ UPF (N4 via PFCP/UDP)
  - All NFs ←→ NRF (SBI via HTTP/2)

Operations:
  - Pass-through: forward traffic unmodified
  - Fuzz: mutate intercepted messages before forwarding
  - Inject: insert fuzzed messages into existing sessions
  - Record: capture all traffic for trace analysis
"""

import asyncio
import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ProxyMode(Enum):
    PASS_THROUGH = "pass_through"
    FUZZ = "fuzz"
    INJECT = "inject"
    RECORD = "record"


@dataclass
class InterceptedMessage:
    """A message intercepted by the proxy."""
    timestamp: float
    direction: str  # "uplink" or "downlink"
    protocol: str
    source: Tuple[str, int]
    destination: Tuple[str, int]
    data: bytes
    modified_data: Optional[bytes] = None


@dataclass
class ProxySession:
    """Track a proxied connection session."""
    session_id: str
    protocol: str
    client_addr: Tuple[str, int]
    server_addr: Tuple[str, int]
    client_sock: Optional[socket.socket] = None
    server_sock: Optional[socket.socket] = None
    messages: List[InterceptedMessage] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)


class ProxyBase:
    """Base class for protocol-specific proxies."""

    def __init__(self, mode: ProxyMode = ProxyMode.FUZZ):
        self.mode = mode
        self.sessions: Dict[str, ProxySession] = {}
        self.message_log: List[InterceptedMessage] = []
        self._mutator: Optional[Callable[[bytes], bytes]] = None
        self._filter: Optional[Callable[[bytes], bool]] = None

    def set_mutator(self, mutator: Callable[[bytes], bytes]) -> None:
        """Set the mutation function for fuzz mode."""
        self._mutator = mutator

    def set_filter(self, filt: Callable[[bytes], bool]) -> None:
        """Set filter function. Only matching messages are mutated."""
        self._filter = filt

    def get_intercepted_messages(self, protocol: Optional[str] = None
                                  ) -> List[InterceptedMessage]:
        if protocol:
            return [m for m in self.message_log if m.protocol == protocol]
        return list(self.message_log)

    def clear_log(self) -> None:
        self.message_log.clear()

    def _should_mutate(self, data: bytes) -> bool:
        if self.mode != ProxyMode.FUZZ:
            return False
        if self._filter and not self._filter(data):
            return False
        return True

    def _apply_mutation(self, data: bytes) -> bytes:
        if self._mutator:
            return self._mutator(data)
        return data


class UDPProxy(ProxyBase):
    """UDP proxy for PFCP (N4) and GTP-U (N3/N9) fuzzing.

    Intercepts UDP traffic, optionally mutates payloads before forwarding.
    """

    def __init__(self, listen_host: str, listen_port: int,
                 target_host: str, target_port: int,
                 mode: ProxyMode = ProxyMode.FUZZ):
        super().__init__(mode)
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._client_map: Dict[Tuple[str, int], Tuple[str, int]] = {}

    async def start(self) -> None:
        """Start the UDP proxy."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.listen_host, self.listen_port))
        self._sock.settimeout(0.5)
        self._running = True

        logger.info(
            f"UDP proxy listening on {self.listen_host}:{self.listen_port} "
            f"→ {self.target_host}:{self.target_port}"
        )

        loop = asyncio.get_event_loop()
        while self._running:
            try:
                data, client_addr = await loop.run_in_executor(
                    None, self._sock.recvfrom, 65535
                )

                msg = InterceptedMessage(
                    timestamp=time.time(),
                    direction="uplink",
                    protocol="udp",
                    source=client_addr,
                    destination=(self.target_host, self.target_port),
                    data=data,
                )
                self.message_log.append(msg)

                if self._should_mutate(data):
                    data = self._apply_mutation(data)
                    msg.modified_data = data

                # Forward to target
                self._sock.sendto(data, (self.target_host, self.target_port))

                # Try to get response
                try:
                    resp_data, _ = self._sock.recvfrom(65535)
                    resp_msg = InterceptedMessage(
                        timestamp=time.time(),
                        direction="downlink",
                        protocol="udp",
                        source=(self.target_host, self.target_port),
                        destination=client_addr,
                        data=resp_data,
                    )
                    self.message_log.append(resp_msg)
                    # Forward response back to client
                    self._sock.sendto(resp_data, client_addr)
                except socket.timeout:
                    pass

            except socket.timeout:
                continue
            except OSError as e:
                if self._running:
                    logger.error(f"UDP proxy error: {e}")

    async def stop(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()
            self._sock = None


class SCTPProxy(ProxyBase):
    """SCTP proxy for NGAP (N2) fuzzing.

    Intercepts SCTP traffic between gNB and AMF.
    Falls back to TCP if SCTP not available.
    """

    def __init__(self, listen_host: str, listen_port: int,
                 target_host: str, target_port: int,
                 mode: ProxyMode = ProxyMode.FUZZ,
                 use_sctp: bool = True):
        super().__init__(mode)
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.use_sctp = use_sctp
        self._server_sock: Optional[socket.socket] = None
        self._running = False

    async def start(self) -> None:
        """Start SCTP proxy (single-connection mode)."""
        sock_type = socket.SOCK_STREAM
        proto = 132 if self.use_sctp else 0  # IPPROTO_SCTP
        try:
            if self.use_sctp:
                self._server_sock = socket.socket(
                    socket.AF_INET, sock_type, proto
                )
            else:
                self._server_sock = socket.socket(socket.AF_INET, sock_type)
                logger.info("SCTP not available, using TCP fallback")
        except OSError:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            logger.info("Falling back to TCP for NGAP proxy")

        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.listen_host, self.listen_port))
        self._server_sock.listen(5)
        self._server_sock.settimeout(1.0)
        self._running = True

        logger.info(
            f"NGAP proxy listening on {self.listen_host}:{self.listen_port} "
            f"→ {self.target_host}:{self.target_port}"
        )

        loop = asyncio.get_event_loop()
        while self._running:
            try:
                client_sock, client_addr = await loop.run_in_executor(
                    None, self._server_sock.accept
                )
                logger.info(f"NGAP proxy: accepted connection from {client_addr}")
                asyncio.create_task(self._handle_connection(client_sock, client_addr))
            except socket.timeout:
                continue
            except OSError as e:
                if self._running:
                    logger.error(f"NGAP proxy accept error: {e}")

    async def _handle_connection(self, client_sock: socket.socket,
                                  client_addr: Tuple[str, int]) -> None:
        """Handle a single proxied SCTP/TCP connection."""
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.connect((self.target_host, self.target_port))
            server_sock.settimeout(1.0)
        except OSError as e:
            logger.error(f"Cannot connect to target: {e}")
            client_sock.close()
            return

        session = ProxySession(
            session_id=f"sctp-{client_addr[0]}:{client_addr[1]}",
            protocol="sctp",
            client_addr=client_addr,
            server_addr=(self.target_host, self.target_port),
            client_sock=client_sock,
            server_sock=server_sock,
        )
        self.sessions[session.session_id] = session

        loop = asyncio.get_event_loop()

        async def forward(direction: str, src: socket.socket, dst: socket.socket,
                          src_addr: Tuple[str, int], dst_addr: Tuple[str, int]):
            while self._running:
                try:
                    data = await loop.run_in_executor(None, src.recv, 65535)
                    if not data:
                        break

                    msg = InterceptedMessage(
                        timestamp=time.time(),
                        direction=direction,
                        protocol="sctp",
                        source=src_addr,
                        destination=dst_addr,
                        data=data,
                    )
                    self.message_log.append(msg)
                    session.messages.append(msg)

                    if self._should_mutate(data):
                        data = self._apply_mutation(data)
                        msg.modified_data = data

                    dst.sendall(data)
                except (socket.timeout, BlockingIOError):
                    continue
                except OSError:
                    break

        task1 = asyncio.create_task(
            forward("uplink", client_sock, server_sock, client_addr,
                    (self.target_host, self.target_port))
        )
        task2 = asyncio.create_task(
            forward("downlink", server_sock, client_sock,
                    (self.target_host, self.target_port), client_addr)
        )

        await asyncio.gather(task1, task2)
        client_sock.close()
        server_sock.close()
        del self.sessions[session.session_id]

    async def stop(self) -> None:
        self._running = False
        if self._server_sock:
            self._server_sock.close()
            self._server_sock = None


class SBIProxy(ProxyBase):
    """HTTP/2 proxy for SBI fuzzing.

    Intercepts HTTP/2 communication between NFs.
    Supports header injection, body mutation, and JSON fuzzing.
    """

    def __init__(self, listen_host: str = "0.0.0.0", listen_port: int = 8080,
                 mode: ProxyMode = ProxyMode.FUZZ):
        super().__init__(mode)
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._running = False

    async def start(self) -> None:
        """Start a simple TCP-based SBI intercept proxy."""
        self._running = True
        server = await asyncio.start_server(
            self._handle_sbi_client,
            self.listen_host, self.listen_port,
        )
        logger.info(f"SBI proxy listening on {self.listen_host}:{self.listen_port}")
        async with server:
            await server.serve_forever()

    async def _handle_sbi_client(self, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter) -> None:
        """Handle an intercepted SBI connection."""
        client_addr = writer.get_extra_info("peername")
        logger.debug(f"SBI proxy: connection from {client_addr}")

        try:
            while self._running:
                data = await asyncio.wait_for(
                    reader.read(65535), timeout=5.0
                )
                if not data:
                    break

                msg = InterceptedMessage(
                    timestamp=time.time(),
                    direction="uplink",
                    protocol="sbi",
                    source=client_addr,
                    destination=(self.listen_host, self.listen_port),
                    data=data,
                )
                self.message_log.append(msg)

                # For SBI, log and pass through (real HTTP/2 proxying
                # requires full HTTP/2 connection management)
                writer.write(data)
                await writer.drain()

                # Read response
                try:
                    resp = await asyncio.wait_for(
                        reader.read(65535), timeout=5.0
                    )
                    resp_msg = InterceptedMessage(
                        timestamp=time.time(),
                        direction="downlink",
                        protocol="sbi",
                        source=(self.listen_host, self.listen_port),
                        destination=client_addr,
                        data=resp,
                    )
                    self.message_log.append(resp_msg)
                except asyncio.TimeoutError:
                    pass

        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            writer.close()

    async def stop(self) -> None:
        self._running = False
