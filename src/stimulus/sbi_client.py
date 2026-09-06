"""SBI stimulus client — HTTP/2 REST client for 5GC Service-Based Interface.

Connects to NFs via HTTP/2, sends fuzzed SBI requests,
and captures responses. Supports all major SBI operations.
"""

import asyncio
import json
import logging
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.codec.sbi_codec import SBICodec, SBI_OPERATIONS, SBIOperation, SBIHttpMethod
from src.codec.base import ParsedMessage

logger = logging.getLogger(__name__)


@dataclass
class SBIResponse:
    status_code: int
    headers: Dict[str, str]
    body: Dict[str, Any]
    raw_body: bytes
    latency_ms: float


class SBIClient:
    """HTTP/2 client for 5GC SBI fuzzing.

    Uses httpx for HTTP/2 support. Falls back to plain HTTP
    for environments without HTTP/2.

    Supported operations:
      - NRF: NFRegister, NFUpdate, NFDeregister, NFDiscover, AccessToken
      - AMF: N1N2MessageTransfer
      - SMF: PDUSessionCreate, Update, Release
      - AUSF: UEAuthenticate
      - UDM: UEContextRegistration
      - PCF: SMPolicyCreate, Update, Delete
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8000",
                 use_http2: bool = True, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.use_http2 = use_http2
        self.verify_ssl = verify_ssl
        self.codec = SBICodec()
        self._http2_enabled = False

    async def connect(self) -> bool:
        """Verify connectivity to the SBI endpoint."""
        try:
            import httpx
            async with httpx.AsyncClient(
                http2=self.use_http2,
                verify=self.verify_ssl,
                timeout=10.0,
            ) as client:
                resp = await client.get(f"{self.base_url}/")
                self._http2_enabled = (resp.http_version == "HTTP/2")
                logger.info(f"SBI client connected, HTTP/2={self._http2_enabled}")
                return True
        except Exception as e:
            logger.warning(f"SBI connectivity check failed: {e}")
            return True  # Don't block — will fail on first actual request

    # ─── High-level SBI operations ────────────────────────────────

    async def nf_register(self, nf_instance_id: str, nf_type: str,
                          ipv4_addresses: List[str]) -> Optional[SBIResponse]:
        """Register an NF with NRF."""
        op_key = "Nnrf_NFManagement/NFRegister"
        body = {
            "nfInstanceId": nf_instance_id,
            "nfType": nf_type,
            "nfStatus": "REGISTERED",
            "ipv4Addresses": ipv4_addresses,
        }
        path = f"/nnrf-nfm/v1/nf-instances/{nf_instance_id}"
        return await self._request(SBIHttpMethod.PUT, path, body)

    async def nf_discover(self, nf_type: str) -> Optional[SBIResponse]:
        """Discover NFs from NRF."""
        path = f"/nnrf-disc/v1/nf-instances?nfType={nf_type}"
        return await self._request(SBIHttpMethod.GET, path)

    async def n1n2_message_transfer(self, ue_context_id: str,
                                     n1_msg: Dict[str, Any],
                                     n2_info: Dict[str, Any],
                                     pdu_session_id: int = 1
                                     ) -> Optional[SBIResponse]:
        """Transfer N1/N2 message via AMF."""
        op_key = "Namf_Communication/N1N2MessageTransfer"
        body = {
            "n1MessageContainer": {
                "n1MessageClass": n1_msg.get("messageClass", "5GMM"),
                "n1MessageContent": n1_msg,
            },
            "n2InfoContainer": {
                "n2InformationClass": n2_info.get("infoClass", "NR"),
            },
            "pduSessionId": pdu_session_id,
        }
        path = f"/namf-comm/v1/ue-contexts/{ue_context_id}/n1-n2-messages"
        return await self._request(SBIHttpMethod.POST, path, body)

    async def pdu_session_create(self, supi: str, dnn: str,
                                  sst: int, sd: str, pdu_session_id: int,
                                  pdu_session_type: str = "IPV4"
                                  ) -> Optional[SBIResponse]:
        """Create PDU Session context via SMF."""
        op_key = "Nsmf_PDUSession/PDUSessionCreateSMContext"
        body = {
            "supi": supi,
            "dnn": dnn,
            "sNssai": {"sst": sst, "sd": sd},
            "pduSessionId": pdu_session_id,
            "pduSessionType": pdu_session_type,
            "sscMode": "SSC_MODE_1",
        }
        path = "/nsmf-pdusession/v1/pdu-sessions"
        return await self._request(SBIHttpMethod.POST, path, body)

    async def ue_authenticate(self, supi_or_suci: str,
                               serving_network: str,
                               auth_type: str = "5G_AKA"
                               ) -> Optional[SBIResponse]:
        """Initiate UE authentication via AUSF."""
        body = {
            "supiOrSuci": supi_or_suci,
            "servingNetworkName": serving_network,
            "authType": auth_type,
        }
        path = "/nausf-auth/v1/ue-authentications"
        return await self._request(SBIHttpMethod.POST, path, body)

    async def ue_context_registration(self, ue_id: str, amf_instance_id: str,
                                       plmn_id: str, amf_id: str,
                                       rat_type: str = "NR"
                                       ) -> Optional[SBIResponse]:
        """Register UE context with UDM."""
        body = {
            "amfInstanceId": amf_instance_id,
            "guami": {"plmnId": plmn_id, "amfId": amf_id},
            "ratType": rat_type,
        }
        path = f"/nudm-uecm/v1/{ue_id}/registrations/amf-3gpp-access"
        return await self._request(SBIHttpMethod.PUT, path, body)

    async def sm_policy_create(self, supi: str, pdu_session_id: int,
                                dnn: str, sst: int, sd: str,
                                notification_uri: str = ""
                                ) -> Optional[SBIResponse]:
        """Create SM Policy via PCF."""
        body = {
            "supi": supi,
            "pduSessionId": pdu_session_id,
            "dnn": dnn,
            "sNssai": {"sst": sst, "sd": sd},
            "notificationUri": notification_uri,
        }
        path = "/npcf-smpolicycontrol/v1/sm-policies"
        return await self._request(SBIHttpMethod.POST, path, body)

    # ─── Raw fuzzing interface ────────────────────────────────────

    async def send_msg(self, msg: ParsedMessage) -> Optional[SBIResponse]:
        """Encode and send a SBI message."""
        encoded = self.codec.encode(msg)
        method = msg.fields.get("method", "POST")
        path = msg.fields.get("path", "/")
        if isinstance(method, SBIHttpMethod):
            method = method.value

        body: Optional[Dict[str, Any]] = msg.fields.get("body")
        if isinstance(body, dict) and not isinstance(body, str):
            body_val: Optional[Dict[str, Any]] = body
        else:
            body_val = None

        return await self._request(
            SBIHttpMethod(method), path, body_val,
            extra_headers=msg.fields.get("headers"),
        )

    async def send_raw(self, data: bytes) -> Optional[SBIResponse]:
        """Send raw HTTP/2 bytes and capture response."""
        import httpx
        import time as _time

        start = _time.monotonic()
        try:
            async with httpx.AsyncClient(
                http2=self.use_http2, verify=self.verify_ssl, timeout=10.0,
            ) as client:
                resp = await client.post(
                    f"{self.base_url}/raw",
                    content=data,
                    headers={"content-type": "application/octet-stream"},
                )
                latency = (_time.monotonic() - start) * 1000

                body: Dict[str, Any] = {}
                try:
                    body = resp.json()
                except (json.JSONDecodeError, ValueError):
                    body = {"_raw": resp.text}

                return SBIResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=body,
                    raw_body=resp.content,
                    latency_ms=latency,
                )
        except Exception as e:
            logger.error(f"SBI raw send error: {e}")
            return None

    # ─── Fuzzing helpers ──────────────────────────────────────────

    async def fuzz_json_body(self, base_body: Dict[str, Any],
                              mutation: str) -> Dict[str, Any]:
        """Apply JSON fuzzing mutation to request body."""
        return self.codec.fuzz_json_body(base_body, mutation)

    async def content_type_attack(self, method: SBIHttpMethod, path: str,
                                   body: Dict[str, Any], fake_ct: str
                                   ) -> Optional[SBIResponse]:
        """Send request with wrong Content-Type."""
        return await self._request(method, path, body,
                                    extra_headers={"content-type": fake_ct})

    async def oversized_body_attack(self, method: SBIHttpMethod, path: str,
                                     base_body: Dict[str, Any]
                                     ) -> Optional[SBIResponse]:
        """Send request with oversized JSON body."""
        big_body = dict(base_body)
        big_body["_padding"] = "X" * 100000
        return await self._request(method, path, big_body)

    # ─── Internal ─────────────────────────────────────────────────

    async def _request(self, method: SBIHttpMethod, path: str,
                        body: Optional[Dict[str, Any]] = None,
                        extra_headers: Optional[Dict[str, str]] = None
                        ) -> Optional[SBIResponse]:
        """Execute an HTTP request against the SBI endpoint."""
        import httpx
        import time as _time

        url = f"{self.base_url}{path}"
        headers: Dict[str, str] = {"content-type": "application/json"}
        if extra_headers:
            headers.update(extra_headers)

        content: Optional[bytes] = None
        if body is not None:
            content = json.dumps(body).encode("utf-8")

        start = _time.monotonic()
        try:
            async with httpx.AsyncClient(
                http2=self.use_http2, verify=self.verify_ssl, timeout=10.0,
            ) as client:
                resp = await client.request(
                    method=method.value, url=url, headers=headers,
                    content=content,
                )
                latency = (_time.monotonic() - start) * 1000

                resp_body: Dict[str, Any] = {}
                try:
                    resp_body = resp.json()
                except (json.JSONDecodeError, ValueError):
                    resp_body = {"_raw_text": resp.text}

                return SBIResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp_body,
                    raw_body=resp.content,
                    latency_ms=latency,
                )
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as e:
            logger.debug(f"SBI request failed (expected during fuzzing): {e}")
            return None
        except Exception as e:
            logger.error(f"SBI request error: {e}")
            return None

    @staticmethod
    def get_available_operations() -> List[str]:
        return list(SBI_OPERATIONS.keys())
