"""Tests for packet capture module."""

import pytest
from netforensic.capture import PacketCapture
from netforensic.utils import setup_logging

logger = setup_logging('ERROR')

class TestPacketCapture:
    """Test packet capture functionality."""
    
    def test_capture_initialization(self):
        """Test PacketCapture initialization."""
        capture = PacketCapture()
        assert capture.captured_packets == []
        assert capture.suspicious_activity == []
        assert capture.is_capturing == False
    
    def test_ioc_loading(self):
        """Test IOC loading functionality."""
        capture = PacketCapture()
        iocs = capture.iocs
        assert isinstance(iocs, list)