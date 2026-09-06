#!/usr/bin/env python3
"""Generate initial seed corpus from scenarios for all protocols.

Usage:
  python scripts/generate_corpus.py --output corpus/
"""

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.codec.nas_codec import NAS5GSCodec
from src.codec.ngap_codec import NGAPCodec
from src.codec.pfcp_codec import PFCPCodec
from src.codec.gtpu_codec import GTPUCodec
from src.codec.sbi_codec import SBICodec
from src.codec.base import ParsedMessage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("corpus")


def generate_nas_seeds(output_dir: Path) -> int:
    codec = NAS5GSCodec()
    count = 0

    messages = [
        ("Registration Request", {
            "5gs_registration_type": 1, "ng_ksi": 0,
            "5gs_mobile_identity_supi": "001010123456789",
        }),
        ("Service Request", {
            "ng_ksi": 0, "tmsi": bytes([0x01, 0x02, 0x03, 0x04]),
        }),
        ("PDU Session Establishment Request", {
            "pdu_session_id": 1, "request_type": 1,
            "ssc_mode": 1, "pdu_session_type": 1,
            "dnn": "internet",
        }),
        ("Authentication Response", {
            "authentication_response_parameter": bytes(16),
        }),
        ("Security Mode Complete", {"imei_sv": bytes([0x00])}),
        ("Registration Complete", {}),
    ]

    for msg_type, fields in messages:
        msg = ParsedMessage(
            protocol="nas-5gs", message_type=msg_type, message_name=msg_type,
            fields=fields,
        )
        try:
            encoded = codec.encode(msg)
            safe_name = msg_type.lower().replace(" ", "_")
            filepath = output_dir / f"{safe_name}.bin"
            with open(filepath, "wb") as f:
                f.write(encoded)
            count += 1
            logger.info(f"NAS: {filepath} ({len(encoded)} bytes)")
        except Exception as e:
            logger.warning(f"NAS {msg_type}: {e}")

    return count


def generate_ngap_seeds(output_dir: Path) -> int:
    codec = NGAPCodec()
    count = 0

    messages = [
        ("InitialUEMessage", {
            "ran_ue_ngap_id": 1, "nas_pdu": bytes(32),
        }),
        ("UplinkNASTransport", {
            "amf_ue_ngap_id": 1, "ran_ue_ngap_id": 1,
            "nas_pdu": bytes(32),
        }),
        ("NGSetupRequest", {
            "gnb_id": bytes([0x00, 0x01, 0x02]),
            "gnb_name": "gNB-001",
        }),
    ]

    for msg_type, fields in messages:
        msg = ParsedMessage(
            protocol="ngap", message_type=msg_type, message_name=msg_type,
            fields=fields,
        )
        try:
            encoded = codec.encode(msg)
            safe_name = msg_type.lower()
            filepath = output_dir / f"{safe_name}.bin"
            with open(filepath, "wb") as f:
                f.write(encoded)
            count += 1
            logger.info(f"NGAP: {filepath} ({len(encoded)} bytes)")
        except Exception as e:
            logger.warning(f"NGAP {msg_type}: {e}")

    return count


def generate_pfcp_seeds(output_dir: Path) -> int:
    codec = PFCPCodec()
    count = 0

    for msg_type in [
        "PFCP Association Setup Request",
        "PFCP Session Establishment Request",
        "PFCP Session Deletion Request",
    ]:
        try:
            msg = codec.random_valid(msg_type)
            encoded = codec.encode(msg)
            safe_name = msg_type.lower().replace(" ", "_").replace("__", "_")
            filepath = output_dir / f"{safe_name}.bin"
            with open(filepath, "wb") as f:
                f.write(encoded)
            count += 1
            logger.info(f"PFCP: {filepath} ({len(encoded)} bytes)")
        except Exception as e:
            logger.warning(f"PFCP {msg_type}: {e}")

    return count


def generate_gtpu_seeds(output_dir: Path) -> int:
    codec = GTPUCodec()
    count = 0

    for msg_type in ["G-PDU", "Echo Request", "Error Indication", "End Marker"]:
        try:
            msg = codec.random_valid(msg_type)
            encoded = codec.encode(msg)
            safe_name = msg_type.lower().replace(" ", "_").replace("-", "_")
            filepath = output_dir / f"{safe_name}.bin"
            with open(filepath, "wb") as f:
                f.write(encoded)
            count += 1
            logger.info(f"GTP-U: {filepath} ({len(encoded)} bytes)")
        except Exception as e:
            logger.warning(f"GTP-U {msg_type}: {e}")

    return count


def generate_sbi_seeds(output_dir: Path) -> int:
    import json
    codec = SBICodec()
    count = 0

    for op_key in codec.get_operation_names():
        try:
            msg = codec.random_valid(op_key)
            # For SBI, save the JSON body
            body = msg.fields.get("body", {})
            safe_name = op_key.replace("/", "_").lower()
            filepath = output_dir / f"{safe_name}.json"
            with open(filepath, "w") as f:
                json.dump({
                    "method": msg.fields.get("method", "POST"),
                    "path": msg.fields.get("path", "/"),
                    "body": body,
                }, f, indent=2)
            count += 1
            logger.info(f"SBI: {filepath}")
        except Exception as e:
            logger.warning(f"SBI {op_key}: {e}")

    return count


def main():
    parser = argparse.ArgumentParser(description="Generate 5G fuzzing seed corpus")
    parser.add_argument("--output", type=str, default="./corpus",
                       help="Corpus output directory")
    args = parser.parse_args()

    base = Path(args.output)
    generators = {
        "nas": (base / "nas", generate_nas_seeds),
        "ngap": (base / "ngap", generate_ngap_seeds),
        "pfcp": (base / "pfcp", generate_pfcp_seeds),
        "gtpu": (base / "gtpu", generate_gtpu_seeds),
        "sbi": (base / "sbi", generate_sbi_seeds),
    }

    total = 0
    for proto, (dir_path, gen_func) in generators.items():
        dir_path.mkdir(parents=True, exist_ok=True)
        n = gen_func(dir_path)
        total += n
        logger.info(f"{proto}: generated {n} seeds")

    logger.info(f"Total seeds generated: {total}")


if __name__ == "__main__":
    main()
