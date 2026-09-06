r"""5GC Deployment Orchestrator — Docker-based lifecycle management.

Manages deployment, health checking, reset, and tear-down for 3 5GC
implementations (Open5GS, free5GC, OAI) as isolated Docker clusters.

Each deployment gets a unique subnet to avoid IP conflicts:
  - Open5GS: 172.23.0.0/24
  - free5GC:  172.24.0.0/24
  - OAI:      172.25.0.0/24

Network topology per deployment:
                   +-----------+
     SCTP:38412 -->|    AMF    |<-- HTTP/2 SBI --> NRF, UDM, AUSF, PCF, etc.
                   +-----+-----+
                         |
                N2 (NGAP) | N1 (NAS)
                         |
               +---------+----------+
               |                    |
      +--------v------+   +--------v--------+
      |   UE/gNB Sim  |   |   SMF           |
      |   (fuzzer)    |   |   N4 (PFCP)     |
      +---------------+   +--------+--------+
                                   |
                           N4 (PFCP)|
                                   |
                           +-------v--------+
                           |   UPF          |
                           |   N3 (GTP-U)   |
                           +----------------+
"""

import asyncio
import json
import logging
import re
import shlex
import subprocess
import time

import httpx
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src import FiveGCImpl, NFType

logger = logging.getLogger(__name__)


# ─── Deployment metadata ──────────────────────────────────────


class DeploymentStatus(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    HEALTHY = "healthy"
    DEGRADED = "degraded"  # Some NFs not healthy
    ERROR = "error"


@dataclass
class NFEndpoint:
    nf_type: NFType
    container_name: str
    ip_address: str
    sbi_port: int  # HTTP/2 Service-Based Interface
    extra_ports: Dict[str, int] = field(default_factory=dict)

    @property
    def sbi_url(self) -> str:
        return f"http://{self.ip_address}:{self.sbi_port}"


@dataclass
class Deployment:
    impl_type: FiveGCImpl
    status: DeploymentStatus = DeploymentStatus.STOPPED
    subnet: str = ""
    network_name: str = ""
    endpoints: Dict[NFType, NFEndpoint] = field(default_factory=dict)
    container_ids: Dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def get_endpoint(self, nf_type: NFType) -> Optional[NFEndpoint]:
        return self.endpoints.get(nf_type)

    def get_amf_sctp_addr(self) -> Optional[str]:
        amf = self.endpoints.get(NFType.AMF)
        return amf.ip_address if amf else None


# ─── Orchestrator ─────────────────────────────────────────────


class DeploymentManager:
    """Manages lifecycle of 5GC Docker deployments.

    Usage:
        mgr = DeploymentManager()
        dep = await mgr.deploy(FiveGCImpl.OPEN5GS)
        # ... run fuzzing ...
        await mgr.destroy(dep)
    """

    # NF health check endpoints and timeouts
    HEALTH_CHECK_CONFIG: Dict[NFType, str] = {
        NFType.AMF: "/namf-comm/v1/status",
        NFType.SMF: "/nsmf-pdusession/v1/status",
        NFType.NRF: "/nnrf-nfm/v1/status",
        NFType.UDM: "/nudm-sdm/v1/status",
        NFType.AUSF: "/nausf-auth/v1/status",
        NFType.PCF: "/npcf-am-policy-control/v1/status",
        NFType.UPF: "",  # UPF uses PFCP, no HTTP health check
    }

    # SBI ports: Open5GS uses 7777, free5GC uses 8000, OAI uses 8080
    SBI_PORT_FOR_IMPL: Dict[FiveGCImpl, int] = {
        FiveGCImpl.OPEN5GS: 7777,
        FiveGCImpl.FREE5GC: 8000,
        FiveGCImpl.OAI: 8080,
    }

    ALL_NF_TYPES: List[NFType] = [
        NFType.AMF, NFType.SMF, NFType.NRF, NFType.UDM, NFType.AUSF,
        NFType.PCF, NFType.NSSF, NFType.BSF, NFType.UDR, NFType.SCP,
    ]

    SUBNET_MAP: Dict[FiveGCImpl, str] = {
        FiveGCImpl.OPEN5GS: "172.23.0.0/24",
        FiveGCImpl.FREE5GC: "172.24.0.0/24",
        FiveGCImpl.OAI: "172.25.0.0/24",
    }

    NETWORK_PREFIX_MAP: Dict[FiveGCImpl, str] = {
        FiveGCImpl.OPEN5GS: "fuzzing-open5gs",
        FiveGCImpl.FREE5GC: "fuzzing-free5gc",
        FiveGCImpl.OAI: "fuzzing-oai",
    }

    def __init__(self, compose_dir: Optional[Path] = None):
        self.compose_dir = compose_dir or Path(__file__).parent
        self.active_deployments: Dict[FiveGCImpl, Deployment] = {}

    # ─── Public API ───────────────────────────────────────────

    async def deploy(self, impl_type: FiveGCImpl,
                     coverage_build: bool = False) -> Deployment:
        """Deploy a complete 5GC stack.

        Steps:
          1. Create isolated Docker network
          2. Start MongoDB/Redis (subscriber DB)
          3. Start NRF first (service registry)
          4. Start remaining control plane NFs
          5. Start UPF (user plane)
          6. Configure subscriber data
          7. Verify health
          8. Return Deployment handle

        Args:
            impl_type: Which 5GC implementation to deploy
            coverage_build: If True, use instrumented images with gcov support

        Returns:
            Deployment handle with NF metadata
        """
        if impl_type in self.active_deployments:
            await self.destroy(self.active_deployments[impl_type])

        deployment = Deployment(
            impl_type=impl_type,
            status=DeploymentStatus.STARTING,
            subnet=self.SUBNET_MAP[impl_type],
            network_name=self.NETWORK_PREFIX_MAP[impl_type],
        )

        # Step 1-5: Launch compose stack (network auto-created)
        compose_file = self._get_compose_file(impl_type, coverage_build)
        await self._run_compose_up(deployment, compose_file)

        # Step 6: Configure subscriber
        await self._configure_subscriber(deployment)

        # Step 7: Discover NFs
        await self._discover_nfs(deployment)

        # Step 8: Health check
        healthy = await self._health_check(deployment)
        deployment.status = DeploymentStatus.HEALTHY if healthy else DeploymentStatus.DEGRADED

        self.active_deployments[impl_type] = deployment
        logger.info(
            f"Deployed {impl_type.value}: "
            f"status={deployment.status.value}, "
            f"{len(deployment.endpoints)} NFs discovered"
        )
        return deployment

    async def destroy(self, deployment: Deployment) -> None:
        """Teardown deployment: stop containers, remove network, clean volumes."""
        compose_file = self._get_compose_file(deployment.impl_type)
        try:
            await self._run_compose_down(deployment, compose_file)
            await self._remove_network(deployment)
        except Exception as e:
            logger.warning(f"Destroy error (may be already stopped): {e}")

        if deployment.impl_type in self.active_deployments:
            del self.active_deployments[deployment.impl_type]
        deployment.status = DeploymentStatus.STOPPED
        logger.info(f"Destroyed {deployment.impl_type.value}")

    async def reset(self, deployment: Deployment) -> None:
        """Quick reset: restart NFs without full redeploy.

        Resets MongoDB subscriber data and restarts containers.
        Much faster than destroy + deploy (seconds vs minutes).
        """
        impl = deployment.impl_type
        await self._run_compose_restart(deployment)
        await self._configure_subscriber(deployment)
        await self._health_check(deployment)
        logger.info(f"Reset {impl.value}")

    async def get_nf_endpoint(self, deployment: Deployment,
                               nf_type: NFType) -> Optional[NFEndpoint]:
        return deployment.get_endpoint(nf_type)

    # ─── Internal: Docker operations ──────────────────────────

    async def _create_network(self, deployment: Deployment) -> None:
        """Create isolated Docker bridge network."""
        cmd = [
            "docker", "network", "create",
            "--driver", "bridge",
            "--subnet", deployment.subnet,
            deployment.network_name,
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.debug(f"Created network {deployment.network_name} ({deployment.subnet})")
        except subprocess.CalledProcessError:
            # Network may already exist
            logger.debug(f"Network {deployment.network_name} already exists")

    async def _remove_network(self, deployment: Deployment) -> None:
        cmd = ["docker", "network", "rm", deployment.network_name]
        subprocess.run(cmd, capture_output=True, text=True)

    async def _run_compose_up(self, deployment: Deployment,
                               compose_file: Path) -> None:
        """Run docker compose up for a deployment.

        Uses ``docker compose up -d`` and then polls ``docker ps``
        until all expected services are running (or a timeout).
        """
        cmd = [
            "docker", "compose", "-f", str(compose_file),
            "-p", deployment.network_name,
            "up", "-d",
        ]
        try:
            result = subprocess.run(
                cmd, check=True, capture_output=True, text=True,
                timeout=600,  # 10 min — accounts for image pulls
            )
            logger.debug(f"docker compose up: {result.stdout[-500:]}")
        except subprocess.CalledProcessError as e:
            logger.error(f"docker compose up failed: {e.stderr}")
            raise
        except subprocess.TimeoutExpired:
            logger.error("docker compose up timed out")
            raise

        # Poll for containers to be running (up to 180 s)
        deadline = time.time() + 180
        network = deployment.network_name
        while time.time() < deadline:
            try:
                ps_result = subprocess.run(
                    ["docker", "ps", "-a", "--filter",
                     f"network={network}",
                     "--format", "{{.Names}}\t{{.Status}}"],
                    capture_output=True, text=True, timeout=10,
                )
                lines = [l for l in ps_result.stdout.strip().split("\n") if l]
                running = [l for l in lines if "Up" in l.split("\t")[1] if len(l.split("\t")) > 1]
                exited = [l for l in lines if "Exited" in l]
                if exited:
                    logger.warning(
                        "Exited containers: %s",
                        ", ".join(l.split("\t")[0] for l in exited),
                    )
                if lines and not exited and len(running) >= len(lines):
                    logger.info(
                        "All %d containers running after %d s",
                        len(running), int(time.time() - (deadline - 180)),
                    )
                    return
            except subprocess.CalledProcessError:
                pass
            time.sleep(5)

        logger.warning("Some containers may not be running after timeout")

    async def _run_compose_down(self, deployment: Deployment,
                                 compose_file: Path) -> None:
        cmd = [
            "docker", "compose", "-f", str(compose_file),
            "-p", deployment.network_name,
            "down", "-v", "--remove-orphans",
        ]
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    async def _run_compose_restart(self, deployment: Deployment) -> None:
        compose_file = self._get_compose_file(deployment.impl_type)
        cmd = [
            "docker", "compose", "-f", str(compose_file),
            "-p", deployment.network_name,
            "restart",
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=120)

    # ─── Internal: NF discovery and health ────────────────────

    async def _discover_nfs(self, deployment: Deployment) -> None:
        """Discover NF endpoints after deployment.

        Uses docker inspect to find container IPs, then maps them to NF types.
        """
        network = deployment.network_name
        cmd = ["docker", "network", "inspect", network]
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            network_info = json.loads(result.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            logger.warning(f"Could not inspect network {network}")
            return

        if not network_info:
            return

        containers = network_info[0].get("Containers", {})
        for container_id, info in containers.items():
            name = info.get("Name", "")
            ip = info.get("IPv4Address", "").split("/")[0] if info.get("IPv4Address") else ""
            nf_type = self._container_name_to_nf(name)

            if nf_type and ip:
                sbi_port = self.SBI_PORT_FOR_IMPL.get(
                    deployment.impl_type, 7777,
                )
                deployment.endpoints[nf_type] = NFEndpoint(
                    nf_type=nf_type,
                    container_name=name,
                    ip_address=ip,
                    sbi_port=sbi_port,
                )
                deployment.container_ids[container_id] = name
                logger.debug(f"Discovered {nf_type.value} at {ip}:{sbi_port} ({name})")

    async def _health_check(self, deployment: Deployment) -> bool:
        """Check health of all NFs via HTTP/2 SBI endpoints."""

        if not deployment.endpoints:
            logger.warning("Health check: no endpoints discovered")
            return False

        all_healthy = True
        for nf_type, endpoint in deployment.endpoints.items():
            health_path = self.HEALTH_CHECK_CONFIG.get(nf_type)
            if not health_path:
                continue  # Skip NFs without HTTP health check (e.g., UPF)

            url = f"http://{endpoint.ip_address}:{endpoint.sbi_port}{health_path}"
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        logger.debug(f"{nf_type.value} healthy")
                    else:
                        logger.warning(f"{nf_type.value} at {url}: HTTP {resp.status_code}")
                        all_healthy = False
            except httpx.HTTPError:
                logger.warning(f"{nf_type.value} unreachable at {url}")
                all_healthy = False

        return all_healthy

    async def _configure_subscriber(self, deployment: Deployment) -> None:
        """Configure test subscriber in the 5GC database.

        Each 5GC uses a different DB (MongoDB for Open5GS, etc.).
        This injects a test IMSI and key for the UE simulator.
        """
        impl = deployment.impl_type
        if impl == FiveGCImpl.OPEN5GS:
            await self._configure_open5gs_subscriber(deployment)
        elif impl == FiveGCImpl.FREE5GC:
            await self._configure_free5gc_subscriber(deployment)
        elif impl == FiveGCImpl.OAI:
            await self._configure_oai_subscriber(deployment)

    async def _configure_open5gs_subscriber(self, deployment: Deployment) -> None:
        """Configure subscriber in Open5GS MongoDB.

        Open5GS stores subscribers in MongoDB 'open5gs' database.
        Test IMSI: 001010000000001, K: 00112233445566778899aabbccddeeff, OPc: ...
        """
        mongo_cmd = (
            f'docker exec $(docker ps -q -f name={deployment.network_name}_mongodb) '
            f'mongosh open5gs --quiet --eval '
            f'\'db.subscribers.insertOne({{'
            f'imsi: "001010000000001", '
            f'security: {{k: "00112233445566778899aabbccddeeff", '
            f'opc: "17b6d3e5e4c3b2a1f0e9d8c7b6a5f4e3", '
            f'amf: "8000"}}, '
            f'slice: [{{sst: 1, default_indicator: true, session: ['
            f'{{name: "internet", type: 1}}]}}]'
            f'}})\''
        )
        subprocess.run(mongo_cmd, shell=True, capture_output=True, text=True)

    async def _configure_free5gc_subscriber(self, deployment: Deployment) -> None:
        """Configure subscriber in free5GC.

        Provisions a test UE subscriber via the WebConsole REST API
        (port 5000), which handles MongoDB document decomposition
        internally.  Falls back to direct MongoDB insertion if the
        WebConsole is not yet reachable.

        The subscriber uses the well-known test SUCI / key / OPc that
        the NAS security layer already encodes into Registration
        Request PDUs.
        """
        supi = "imsi-001010000000001"
        key = "00112233445566778899aabbccddeeff"
        opc = "63bfa50ee6523365ff14c1f45f88737d"
        plmn_id = "00101"

        subscriber = {
            "plmnID": plmn_id,
            "ueId": supi,
            "AuthenticationSubscription": {
                "authenticationMethod": "5G_AKA",
                "permanentKey": {"permanentKeyValue": key},
                "sequenceNumber": "000000000000",
                "authenticationManagementField": "8000",
                "milenage": {"op": {"opValue": ""}},
                "opc": {"opcValue": opc},
            },
            "AccessAndMobilitySubscriptionData": {
                "servingPlmnId": plmn_id,
                "subscribedUeAmbr": {
                    "uplink": "1 Gbps",
                    "downlink": "1 Gbps",
                },
                "nssai": {
                    "defaultSingleNssais": [
                        {"sst": 1, "sd": "010203"},
                    ],
                },
            },
            "SessionManagementSubscriptionData": [
                {
                    "singleNssai": {"sst": 1, "sd": "010203"},
                    "dnnConfigurations": {
                        "internet": {
                            "pduSessionTypes": {
                                "defaultSessionType": "IPV4",
                                "allowedSessionTypes": ["IPV4"],
                            },
                            "sscModes": {
                                "defaultSscMode": "SSC_MODE_1",
                                "allowedSscModes": ["SSC_MODE_1"],
                            },
                            "5gQosProfile": {
                                "5qi": 9,
                                "arp": {"priorityLevel": 8},
                                "priorityLevel": 8,
                            },
                            "sessionAmbr": {
                                "uplink": "1 Gbps",
                                "downlink": "1 Gbps",
                            },
                        },
                    },
                },
            ],
        }

        webui_host = "172.24.0.130"
        webui_url = f"http://{webui_host}:5000/api/subscriber/{supi}/{plmn_id}"

        # Retry loop: WebConsole may still be initialising
        for attempt in range(12):
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(webui_url, json=subscriber)
                if resp.status_code in (200, 201):
                    logger.info(
                        "free5GC subscriber %s provisioned via WebConsole "
                        "(attempt %d)", supi, attempt + 1,
                    )
                    return
                logger.debug(
                    "WebConsole attempt %d: HTTP %d %s",
                    attempt + 1, resp.status_code, resp.text[:120],
                )
            except httpx.HTTPError as exc:
                logger.debug(
                    "WebConsole attempt %d: %s", attempt + 1, exc,
                )
            await asyncio.sleep(2)

        # Fallback: insert directly into MongoDB so the fuzzer can
        # still authenticate (the WebConsole does the same internally)
        logger.warning(
            "WebConsole unreachable after retries — "
            "inserting subscriber directly into MongoDB"
        )
        await self._configure_free5gc_subscriber_mongo(deployment)

    async def _configure_free5gc_subscriber_mongo(
        self, deployment: Deployment,
    ) -> None:
        """Direct MongoDB insertion fallback for free5GC subscriber."""
        mongo_container = f"{deployment.network_name}-mongodb"

        # ── authentication subscription ─────────────────────────
        auth_cmd = (
            f"docker exec {shlex.quote(mongo_container)} "
            f"mongosh free5gc --quiet --eval "
            f"'db.getCollection(\"subscriptionData.authenticationData."
            f"authenticationSubscription\").replaceOne("
            f'{{ueId: "imsi-001010000000001"}},'
            f'{{ueId: "imsi-001010000000001",'
            f'authenticationMethod: "5G_AKA",'
            f'permanentKey: {{permanentKeyValue: '
            f'"00112233445566778899aabbccddeeff"}},'
            f'sequenceNumber: "000000000000",'
            f'authenticationManagementField: "8000",'
            f'milenage: {{op: {{opValue: ""}}}},'
            f'opc: {{opcValue: "63bfa50ee6523365ff14c1f45f88737d"}}'
            f'}}, {{upsert: true}})'
            f"'"
        )
        subprocess.run(
            auth_cmd, shell=True, capture_output=True, text=True, timeout=30,
        )

        # ── AM subscription data ────────────────────────────────
        am_cmd = (
            f"docker exec {shlex.quote(mongo_container)} "
            f"mongosh free5gc --quiet --eval "
            f"'db.getCollection(\"subscriptionData.provisionedData."
            f"amData\").replaceOne("
            f'{{ueId: "imsi-001010000000001"}},'
            f'{{ueId: "imsi-001010000000001",'
            f'servingPlmnId: "00101",'
            f'subscribedUeAmbr: {{uplink: "1 Gbps", downlink: "1 Gbps"}},'
            f'nssai: {{defaultSingleNssais: [{{sst: 1, sd: "010203"}}]}}'
            f'}}, {{upsert: true}})'
            f"'"
        )
        subprocess.run(
            am_cmd, shell=True, capture_output=True, text=True, timeout=30,
        )

        # ── SM subscription data ────────────────────────────────
        sm_cmd = (
            f"docker exec {shlex.quote(mongo_container)} "
            f"mongosh free5gc --quiet --eval "
            f"'db.getCollection(\"subscriptionData.provisionedData."
            f"smData\").replaceOne("
            f'{{ueId: "imsi-001010000000001", '
            f'"singleNssai.sst": 1, "singleNssai.sd": "010203"}},'
            f'{{ueId: "imsi-001010000000001",'
            f'servingPlmnId: "00101",'
            f'singleNssai: {{sst: 1, sd: "010203"}},'
            f'dnnConfigurations: {{'
            f'internet: {{'
            f'pduSessionTypes: {{defaultSessionType: "IPV4",'
            f'allowedSessionTypes: ["IPV4"]}},'
            f'sscModes: {{defaultSscMode: "SSC_MODE_1",'
            f'allowedSscModes: ["SSC_MODE_1"]}},'
            f'"5gQosProfile": {{"5qi": 9, arp: {{priorityLevel: 8}},'
            f'priorityLevel: 8}},'
            f'sessionAmbr: {{uplink: "1 Gbps", downlink: "1 Gbps"}}'
            f'}}'
            f'}}'
            f'}}, {{upsert: true}})'
            f"'"
        )
        subprocess.run(
            sm_cmd, shell=True, capture_output=True, text=True, timeout=30,
        )
        logger.info("free5GC subscriber inserted via direct MongoDB")

    async def _configure_oai_subscriber(self, deployment: Deployment) -> None:
        """Configure subscriber in OAI 5G Core.

        OAI stores subscriber data in MySQL (oai_db database).  The
        AMF reads authentication and subscription records directly
        from this database — there is no separate WebUI.

        We insert the minimum set of rows needed for registration
        and PDU-session establishment: AuthenticationSubscription,
        AccessAndMobilitySubscriptionData, and
        SessionManagementSubscriptionData.
        """
        mysql_container = f"{deployment.network_name}-mysql"
        supi = "001010000000001"

        sql_statements = (
            # Ensure tables exist (OAI schema may not be initialised)
            "CREATE TABLE IF NOT EXISTS AuthenticationSubscription ("
            "  ueid VARCHAR(20) NOT NULL PRIMARY KEY,"
            "  authenticationMethod VARCHAR(20) NOT NULL DEFAULT '5G_AKA',"
            "  encPermanentKey VARCHAR(128) NOT NULL,"
            "  protectionParameterId VARCHAR(128) NOT NULL,"
            "  sequenceNumber VARCHAR(128) NOT NULL,"
            "  authenticationManagementField VARCHAR(10) NOT NULL DEFAULT '8000',"
            "  algorithmId VARCHAR(10) NOT NULL DEFAULT 'milenage',"
            "  encOpcKey VARCHAR(128) NOT NULL,"
            "  encTopcKey VARCHAR(128) DEFAULT NULL,"
            "  vectorGenerationInHss VARCHAR(1) NOT NULL DEFAULT '1',"
            "  n5gcAuthMethod VARCHAR(20) NOT NULL DEFAULT 'EAP_AKA_PRIME',"
            "  rgAuthenticationInd VARCHAR(1) NOT NULL DEFAULT '0',"
            "  supi VARCHAR(20) DEFAULT NULL"
            ");"
            ""
            "CREATE TABLE IF NOT EXISTS AccessAndMobilitySubscriptionData ("
            "  ueid VARCHAR(20) NOT NULL PRIMARY KEY,"
            "  servingPlmnId VARCHAR(15) NOT NULL DEFAULT '00101',"
            "  subscribedUeAmbrDown VARCHAR(20) DEFAULT '1 Gbps',"
            "  subscribedUeAmbrUp VARCHAR(20) DEFAULT '1 Gbps',"
            "  nssaiDefaultSst INT DEFAULT 1,"
            "  nssaiDefaultSd VARCHAR(6) DEFAULT '010203'"
            ");"
            ""
            "CREATE TABLE IF NOT EXISTS SessionManagementSubscriptionData ("
            "  id INT AUTO_INCREMENT PRIMARY KEY,"
            "  ueid VARCHAR(20) NOT NULL,"
            "  servingPlmnId VARCHAR(15) DEFAULT '00101',"
            "  singleNssaiSst INT DEFAULT 1,"
            "  singleNssaiSd VARCHAR(6) DEFAULT '010203',"
            "  dnn VARCHAR(50) DEFAULT 'default',"
            "  defaultSessionType VARCHAR(10) DEFAULT 'IPV4',"
            "  sscMode VARCHAR(20) DEFAULT 'SSC_MODE_1',"
            "  5qi INT DEFAULT 9,"
            "  priorityLevel INT DEFAULT 8,"
            "  sessionAmbrDown VARCHAR(20) DEFAULT '1 Gbps',"
            "  sessionAmbrUp VARCHAR(20) DEFAULT '1 Gbps'"
            ");"
            ""
            # Upsert AuthenticationSubscription
            "REPLACE INTO AuthenticationSubscription ("
            "  ueid, authenticationMethod, encPermanentKey,"
            "  protectionParameterId, sequenceNumber,"
            "  authenticationManagementField, algorithmId,"
            "  encOpcKey, vectorGenerationInHss,"
            "  n5gcAuthMethod, rgAuthenticationInd, supi"
            ") VALUES ("
            f"  '{supi}', '5G_AKA',"
            f"  '00112233445566778899aabbccddeeff',"
            f"  '00112233445566778899aabbccddeeff',"
            f"  '000000000000', '8000', 'milenage',"
            f"  '63bfa50ee6523365ff14c1f45f88737d',"
            f"  '1', 'EAP_AKA_PRIME', '0', '{supi}'"
            ");"
            ""
            # Upsert AccessAndMobilitySubscriptionData
            "REPLACE INTO AccessAndMobilitySubscriptionData ("
            "  ueid, servingPlmnId, subscribedUeAmbrDown,"
            "  subscribedUeAmbrUp, nssaiDefaultSst, nssaiDefaultSd"
            ") VALUES ("
            f"  '{supi}', '00101', '1 Gbps', '1 Gbps', 1, '010203'"
            ");"
            ""
            # Upsert SessionManagementSubscriptionData
            "REPLACE INTO SessionManagementSubscriptionData ("
            "  id, ueid, servingPlmnId, singleNssaiSst, singleNssaiSd,"
            "  dnn, defaultSessionType, sscMode, 5qi,"
            "  priorityLevel, sessionAmbrDown, sessionAmbrUp"
            ") VALUES ("
            f"  1, '{supi}', '00101', 1, '010203',"
            f"  'default', 'IPV4', 'SSC_MODE_1', 9, 8, '1 Gbps', '1 Gbps'"
            ");"
        )

        cmd = [
            "docker", "exec", "-i", mysql_container,
            "mysql", "-u", "root", "-poai_password", "oai_db",
        ]
        for attempt in range(12):
            try:
                result = subprocess.run(
                    cmd,
                    input=sql_statements,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.returncode == 0:
                    logger.info(
                        "OAI subscriber %s provisioned via MySQL (attempt %d)",
                        supi, attempt + 1,
                    )
                    return
                logger.debug(
                    "OAI MySQL attempt %d: exit %d, %s",
                    attempt + 1, result.returncode, result.stderr[:200],
                )
            except subprocess.TimeoutExpired:
                logger.debug("OAI MySQL attempt %d timed out", attempt + 1)
            except FileNotFoundError:
                logger.error("docker CLI not found — cannot configure OAI subscriber")
                return
            await asyncio.sleep(2)

        logger.warning(
            "OAI subscriber provision failed after 12 attempts — MySQL may not be ready"
        )

    # ─── Helpers ──────────────────────────────────────────────

    def _get_compose_file(self, impl_type: FiveGCImpl,
                           coverage: bool = False) -> Path:
        impl_dir = impl_type.value
        suffix = "-coverage" if coverage else ""
        return self.compose_dir / impl_dir / f"docker-compose{suffix}.yml"

    @staticmethod
    def _container_name_to_nf(name: str) -> Optional[NFType]:
        """Map container name to NF type."""
        name_lower = name.lower()
        mapping = {
            "amf": NFType.AMF,
            "smf": NFType.SMF,
            "upf": NFType.UPF,
            "nrf": NFType.NRF,
            "udm": NFType.UDM,
            "ausf": NFType.AUSF,
            "pcf": NFType.PCF,
            "udr": NFType.UDR,
            "nssf": NFType.NSSF,
            "bsf": NFType.BSF,
            "scp": NFType.SCP,
        }
        for key, nf_type in mapping.items():
            if key in name_lower:
                return nf_type
        return None


# ─── Container health monitoring ──────────────────────────────


class ContainerHealthMonitor:
    """Monitor container health during fuzzing.

    Detects:
      - Container stopped/crashed
      - OOM killed
      - Exit code analysis
      - Restart loops
    """

    def __init__(self, deployment: Deployment):
        self.deployment = deployment

    def check_containers(self) -> Dict[str, str]:
        """Check all containers in the deployment.

        Returns dict of container_name -> status.
        """
        statuses: Dict[str, str] = {}
        for cid, name in self.deployment.container_ids.items():
            cmd = ["docker", "inspect", "--format",
                   "{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}",
                   cid]
            try:
                result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                parts = result.stdout.strip().split("|")
                status = parts[0] if len(parts) > 0 else "unknown"
                exit_code = parts[1] if len(parts) > 1 else ""
                oom = parts[2] if len(parts) > 2 else "false"

                if status != "running":
                    status_detail = f"{status}"
                    if exit_code and exit_code != "0":
                        status_detail += f" (exit={exit_code})"
                    if oom == "true":
                        status_detail += " [OOM]"
                    statuses[name] = status_detail
                else:
                    statuses[name] = "running"
            except subprocess.CalledProcessError:
                statuses[name] = "inspect_failed"

        return statuses

    def get_crashed_containers(self) -> List[Tuple[str, str]]:
        """Return list of (container_name, crash_reason)."""
        crashed = []
        for name, status in self.check_containers().items():
            if status != "running":
                crashed.append((name, status))
        return crashed

    def inspect_crash(self, container_id: str) -> Dict[str, Any]:
        """Get detailed crash info from a container."""
        cmd = ["docker", "inspect", container_id]
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            info = json.loads(result.stdout)[0]
            state = info.get("State", {})
            return {
                "status": state.get("Status"),
                "exit_code": state.get("ExitCode"),
                "oom_killed": state.get("OOMKilled"),
                "error": state.get("Error"),
                "started_at": state.get("StartedAt"),
                "finished_at": state.get("FinishedAt"),
                "health": state.get("Health", {}).get("Log", []),
            }
        except (subprocess.CalledProcessError, json.JSONDecodeError, IndexError):
            return {"status": "inspect_failed"}
