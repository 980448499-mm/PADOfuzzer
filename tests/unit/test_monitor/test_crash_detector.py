"""Unit tests for crash detector and monitoring components."""

import pytest
from unittest.mock import MagicMock
from src.monitor.component_monitor import CrashDetector, LogHarvester
from src.deployment.orchestrator import Deployment, DeploymentStatus
from src import FiveGCImpl


class TestCrashDetector:
    @pytest.fixture
    def mock_deployment(self):
        return Deployment(
            impl_type=FiveGCImpl.OPEN5GS,
            status=DeploymentStatus.HEALTHY,
            subnet="172.23.0.0/24",
            network_name="fuzzing-test",
        )

    def test_create_detector(self, mock_deployment):
        detector = CrashDetector(mock_deployment)
        assert detector is not None
        assert detector.deployment is mock_deployment

    def test_severity_map(self, mock_deployment):
        detector = CrashDetector(mock_deployment)
        assert "SEGV" in detector.SEVERITY_MAP
        assert "ASAN_ERROR" in detector.SEVERITY_MAP
        assert detector.SEVERITY_MAP["SEGV"].value == "critical"

    def test_initial_state(self, mock_deployment):
        detector = CrashDetector(mock_deployment)
        assert len(detector._detected_hashes) == 0

    def test_has_harvester(self, mock_deployment):
        detector = CrashDetector(mock_deployment)
        assert isinstance(detector.harvester, LogHarvester)


class TestLogHarvester:
    @pytest.fixture
    def mock_deployment(self):
        return Deployment(
            impl_type=FiveGCImpl.OPEN5GS,
            status=DeploymentStatus.HEALTHY,
        )

    def test_create_harvester(self, mock_deployment):
        harvester = LogHarvester(mock_deployment)
        assert harvester is not None

    def test_key_patterns(self, mock_deployment):
        harvester = LogHarvester(mock_deployment)
        assert len(harvester.KEY_PATTERNS) > 0
        for name, pattern in harvester.KEY_PATTERNS.items():
            assert name is not None
            assert pattern is not None
