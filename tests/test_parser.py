"""Tests for PCAP parser module."""

import pytest
import tempfile
import os
from netforensic.parser import PCAPAnalyzer
from netforensic.utils import setup_logging

logger = setup_logging('ERROR')

class TestPCAPAnalyzer:
    """Test PCAP analysis functionality."""
    
    def test_analyzer_initialization(self):
        """Test PCAPAnalyzer initialization."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            f.write(b'dummy data')
            temp_file = f.name
        
        try:
            analyzer = PCAPAnalyzer(temp_file)
            assert analyzer.pcap_file == temp_file
            assert analyzer.iocs == []
        finally:
            os.unlink(temp_file)
    
    def test_invalid_pcap_file(self):
        """Test behavior with invalid PCAP file."""
        with pytest.raises(Exception):
            analyzer = PCAPAnalyzer("nonexistent.pcap")
            analyzer.parse()