"""Protocol-aware send function factory.

Routes fuzzed PDUs from the fuzzing engine to the correct real-world
protocol client based on (NFType, ProtocolType).  Plugs into
FuzzingEngine.set_send_function() so the core loop can talk to live
5GC deployments.

Protocol → client mapping:
  NAS  → UEGNBSimulator (SCTP N2 to AMF)
  NGAP → UEGNBSimulator (SCTP N2 to AMF)
  PFCP → PFCPClient      (UDP N4 to UPF)
  SBI  → SBIClient        (HTTP/2 to any NF)
  GTPU → GTPUClient       (UDP N3 to UPF)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional, Tuple

from src import NFType, ProtocolType

logger = logging.getLogger(__name__)


class SendFunctionFactory:
    """Creates a ``send_fn`` callable wired to live protocol clients.

    The returned function has signature::

        async def send_fn(nf_type: NFType, protocol: ProtocolType,
                          pdu: bytes) -> Optional[bytes]

    It dispatches to the appropriate client, encodes/decodes as needed,
    and returns the raw response bytes (or None on timeout / error).
    """

    def __init__(self) -> None:
        self._nas_client: Optional[Any] = None   # UEGNBSimulator
        self._ngap_client: Optional[Any] = None  # UEGNBSimulator (same instance)
        self._pfcp_client: Optional[Any] = None  # PFCPClient
        self._sbi_client: Optional[Any] = None   # SBIClient
        self._gtpu_client: Optional[Any] = None  # GTPUClient

    # -- setters so callers can inject pre-connected clients ------------

    def set_nas_client(self, client: Any) -> None:
        """Attach a UEGNBSimulator for NAS fuzzing."""
        self._nas_client = client

    def set_ngap_client(self, client: Any) -> None:
        """Attach a UEGNBSimulator for NGAP fuzzing (usually same as NAS)."""
        self._ngap_client = client

    def set_pfcp_client(self, client: Any) -> None:
        self._pfcp_client = client

    def set_sbi_client(self, client: Any) -> None:
        self._sbi_client = client

    def set_gtpu_client(self, client: Any) -> None:
        self._gtpu_client = client

    # -- build the closure -------------------------------------------------

    def build(self) -> callable:
        """Return the ``send_fn`` closure.

        Usage::

            factory = SendFunctionFactory()
            factory.set_nas_client(sim)
            engine.set_send_function(factory.build())
        """
        nas = self._nas_client
        ngap = self._ngap_client
        pfcp = self._pfcp_client
        sbi = self._sbi_client
        gtpu = self._gtpu_client

        async def _send(
            nf_type: NFType,
            protocol: ProtocolType,
            pdu: bytes,
        ) -> Optional[bytes]:
            # -- NAS -------------------------------------------------
            if protocol == ProtocolType.NAS:
                if nas is None:
                    logger.warning("NAS client not configured; dropping PDU")
                    return None
                nas.send_raw_nas(nas.ues.get(list(nas.ues.keys())[0]) if nas.ues else None, pdu)
                resp = nas.recv_response(timeout=3.0)
                return resp

            # -- NGAP ------------------------------------------------
            if protocol == ProtocolType.NGAP:
                client = ngap or nas
                if client is None:
                    logger.warning("NGAP client not configured; dropping PDU")
                    return None
                client.send_raw_ngap(pdu)
                resp = client.recv_response(timeout=3.0)
                return resp

            # -- PFCP ------------------------------------------------
            if protocol == ProtocolType.PFCP:
                if pfcp is None:
                    logger.warning("PFCP client not configured; dropping PDU")
                    return None
                result = await pfcp.send_raw(pdu)
                return result.raw_bytes if result else None

            # -- SBI -------------------------------------------------
            if protocol == ProtocolType.SBI:
                if sbi is None:
                    logger.warning("SBI client not configured; dropping PDU")
                    return None
                result = await sbi.send_raw(pdu)
                return result.raw_body if result else None

            # -- GTP-U -----------------------------------------------
            if protocol == ProtocolType.GTPU:
                if gtpu is None:
                    logger.warning("GTP-U client not configured; dropping PDU")
                    return None
                result = await gtpu.send_raw(pdu)
                return result.raw_bytes if result else None

            logger.warning("Unknown protocol %s; dropping PDU", protocol)
            return None

        return _send


# -- standalone helper for quick wiring ---------------------------------


async def make_send_fn_for_deployment(
    deployment: Any,  # Deployment
) -> Tuple[callable, Dict[str, Any]]:
    """Convenience: create connected clients for all protocols in one call.

    Returns (send_fn, clients_dict) where clients_dict holds refs to all
    created clients so the caller can close them later.
    """
    from src.deployment.orchestrator import Deployment
    from src.stimulus.ue_gnb_simulator import UEGNBSimulator
    from src.stimulus.pfcp_client import PFCPClient
    from src.stimulus.sbi_client import SBIClient
    from src.stimulus.gtpu_client import GTPUClient

    factory = SendFunctionFactory()
    clients: Dict[str, Any] = {}

    # -- UE/gNB simulator for NAS + NGAP -------------------------------
    amf_ep = deployment.get_endpoint(NFType.AMF)
    if amf_ep is not None:
        sim = UEGNBSimulator(amf_addr=amf_ep.ip_address, amf_port=amf_ep.extra_ports.get("sctp", 38412))
        sim.connect()
        # Register a test UE so there is a context for fuzzed NAS
        try:
            sim.register_ue("001010123456789")
        except Exception:
            logger.warning("Pre-registration of test UE failed (AMF may not be ready)")
        factory.set_nas_client(sim)
        factory.set_ngap_client(sim)
        clients["nas_ngap"] = sim
        logger.info("UE/gNB simulator connected to AMF at %s", amf_ep.ip_address)
    else:
        logger.warning("No AMF endpoint discovered — NAS/NGAP fuzzing unavailable")

    # -- PFCP client ---------------------------------------------------
    upf_ep = deployment.get_endpoint(NFType.UPF)
    if upf_ep is not None:
        pfcp = PFCPClient(upf_host=upf_ep.ip_address, upf_port=upf_ep.extra_ports.get("pfcp", 8805))
        await pfcp.connect()
        factory.set_pfcp_client(pfcp)
        clients["pfcp"] = pfcp
        logger.info("PFCP client connected to UPF at %s", upf_ep.ip_address)

    # -- SBI client ----------------------------------------------------
    # Pick the first NF with an SBI endpoint (prefer NRF for discovery)
    sbi_ep = None
    for nf_type in (NFType.NRF, NFType.AMF, NFType.SMF, NFType.UDM):
        sbi_ep = deployment.get_endpoint(nf_type)
        if sbi_ep is not None:
            break
    if sbi_ep is not None:
        sbi = SBIClient(base_url=sbi_ep.sbi_url)
        await sbi.connect()
        factory.set_sbi_client(sbi)
        clients["sbi"] = sbi
        logger.info("SBI client connected to %s at %s", sbi_ep.nf_type.value, sbi_ep.sbi_url)

    # -- GTP-U client --------------------------------------------------
    if upf_ep is not None:
        gtpu = GTPUClient(upf_host=upf_ep.ip_address, upf_port=upf_ep.extra_ports.get("gtpu", 2152))
        await gtpu.connect()
        factory.set_gtpu_client(gtpu)
        clients["gtpu"] = gtpu
        logger.info("GTP-U client connected to UPF at %s:%d", upf_ep.ip_address, upf_ep.extra_ports.get("gtpu", 2152))

    return factory.build(), clients
