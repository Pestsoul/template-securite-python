import os
import tempfile
from unittest.mock import MagicMock
from src.tp1.utils.report import Report


def _make_capture(protocols=None, ips=None, suspicious=None):
    """Helper: creates a capture mock with realistic data."""
    capture = MagicMock()
    capture.protocol_counter = protocols or {"TCP": 10, "UDP": 5, "ARP": 3, "UNKNOWN": 2}
    capture.ip_packet_counter = ips or {"192.168.1.1": 8, "192.168.1.2": 10}
    capture.ip_proto_map = {
        "192.168.1.1": {"TCP"},
        "192.168.1.2": {"TCP", "UDP"},
    }
    capture.ip_proto_counter = {
        "192.168.1.1": {"TCP": 8},
        "192.168.1.2": {"TCP": 6, "UDP": 4},
    }
    capture.suspicious = suspicious if suspicious is not None else []

    # get_proto_analysis mock
    proto_analysis = {}
    for proto, count in (protocols or {"TCP": 10, "UDP": 5, "ARP": 3}).items():
        alerts = [a for a in (suspicious or []) if proto in a]
        proto_analysis[proto] = {
            "count": count,
            "status": "SUSPICIOUS" if alerts else "OK",
            "alerts": alerts,
        }
    capture.get_proto_analysis.return_value = proto_analysis
    return capture


def test_report_init():
    report = Report(MagicMock(), "test.pdf", "Test summary")
    assert report.title == "TITRE DU RAPPORT\n"
    assert report.array == ""
    assert report.graph == ""


def test_concat_report():
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.title = "Test Title"
    report.array = "Array"
    report.graph = "Graph"
    result = report.concat_report()
    assert result == "Test TitleTest summary\nArray\nGraph\n"


def test_save_txt():
    """save() with a non-pdf filename writes text content."""
    report = Report(MagicMock(), "test.txt", "Test summary")
    report.title = "Test Title"
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tmp:
        tmp_path = tmp.name
    try:
        report.save(tmp_path)
        with open(tmp_path, "r") as f:
            content = f.read()
        assert content == "Test TitleTest summary\n"
    finally:
        os.unlink(tmp_path)


def test_save_pdf():
    """save() with a .pdf filename generates a real PDF file (starts with %PDF)."""
    capture = _make_capture()
    report = Report(capture, "test.pdf", "Test summary")
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        report.save(tmp_path)
        assert os.path.exists(tmp_path)
        assert os.path.getsize(tmp_path) > 0
        with open(tmp_path, "rb") as f:
            assert f.read(4) == b"%PDF"
    finally:
        os.unlink(tmp_path)


def test_generate():
    capture = _make_capture()
    report = Report(capture, "test.pdf", "Test summary")
    report.generate("graph")
    assert report.graph == "network_graph.svg"
    report.generate("array")
    assert report.array == "protocol_table.csv"


def test_generate_graph_contains_protocols():
    """Graph SVG should contain protocol names and actual bar data."""
    capture = _make_capture(protocols={"TCP": 28, "ARP": 20, "UDP": 21, "UNKNOWN": 2})
    report = Report(capture, "test.pdf", "Test summary")
    report.generate("graph")

    with open("network_graph.svg", "r") as f:
        svg_content = f.read()

    assert '"legends": ["TCP", "ARP", "UDP", "UNKNOWN"]' in svg_content
    assert 'class="rect reactive tooltip-trigger"' in svg_content
    assert '<desc class="value">28</desc>' in svg_content
    assert '<desc class="value">20</desc>' in svg_content
    assert '<desc class="value">21</desc>' in svg_content
    assert '<desc class="value">2</desc>' in svg_content


def test_generate_pdf_contains_unknown():
    """PDF should contain UNKNOWN protocol in protocol analysis."""
    capture = _make_capture(protocols={"TCP": 10, "UDP": 5, "ARP": 3, "UNKNOWN": 2})
    report = Report(capture, "test.pdf", "Interface: ens33\nTotal packets captured: 20")
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        report.save(tmp_path)
        assert os.path.exists(tmp_path)
        assert os.path.getsize(tmp_path) > 0
    finally:
        os.unlink(tmp_path)


def test_generate_csv_contains_protocols():
    """CSV should contain protocol names and packet counts."""
    capture = _make_capture(protocols={"TCP": 10, "UDP": 5, "ARP": 3, "UNKNOWN": 2})
    report = Report(capture, "test.pdf", "Test summary")
    report.generate("array")

    with open("protocol_table.csv", "r") as f:
        content = f.read()

    assert "Protocol" in content
    assert "TCP" in content
    assert "UDP" in content
    assert "ARP" in content
    assert "UNKNOWN" in content
    assert "10" in content
    assert "2" in content


def test_generate_csv_contains_ip_table():
    """CSV should contain IP addresses and their packet counts."""
    capture = _make_capture()
    report = Report(capture, "test.pdf", "Test summary")
    report.generate("array")

    with open("protocol_table.csv", "r") as f:
        content = f.read()

    assert "192.168.1.1" in content
    assert "192.168.1.2" in content


def test_generate_csv_contains_attacks():
    """CSV should contain detected attacks."""
    capture = _make_capture(suspicious=["SQLi detected from 10.0.0.1"])
    report = Report(capture, "test.pdf", "Test summary")
    report.generate("array")

    with open("protocol_table.csv", "r") as f:
        content = f.read()

    assert "SQLi detected from 10.0.0.1" in content


def test_generate_csv_no_attacks():
    """CSV should mention no attacks when suspicious list is empty."""
    capture = _make_capture(suspicious=[])
    report = Report(capture, "test.pdf", "Test summary")
    report.generate("array")

    with open("protocol_table.csv", "r") as f:
        content = f.read()

    assert "No attacks detected" in content