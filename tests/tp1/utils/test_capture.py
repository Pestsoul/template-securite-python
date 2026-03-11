# test_capture.py
from unittest.mock import patch, MagicMock
from src.tp1.utils.capture import Capture
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP


# ---------- Helpers pour créer des faux paquets ----------

# Crée un faux paquet TCP avec IP source et destination
def _make_tcp_packet(src="192.168.1.1", dst="192.168.1.2"):
    fake_ip = MagicMock()
    fake_ip.proto = 6
    fake_ip.src = src
    fake_ip.dst = dst
    packet = MagicMock()
    packet.__contains__.side_effect = lambda x: x in [IP, TCP]
    packet.__getitem__.side_effect = lambda x: fake_ip if x is IP else MagicMock()
    packet.haslayer.return_value = True
    return packet


# Crée un faux paquet UDP avec IP source et destination
def _make_udp_packet(src="10.0.0.1", dst="10.0.0.2"):
    fake_ip = MagicMock()
    fake_ip.proto = 17
    fake_ip.src = src
    fake_ip.dst = dst
    packet = MagicMock()
    packet.__contains__.side_effect = lambda x: x in [IP, UDP]
    packet.__getitem__.side_effect = lambda x: fake_ip if x is IP else MagicMock()
    packet.haslayer.return_value = False
    return packet


# Crée un faux paquet TCP avec payload SQLi
def _make_sqli_packet(src="192.168.1.100", dst="192.168.1.200"):
    fake_ip = MagicMock()
    fake_ip.proto = 6
    fake_ip.src = src
    fake_ip.dst = dst
    fake_tcp = MagicMock()
    fake_tcp.payload = b"SELECT * FROM users"
    packet = MagicMock()
    packet.__contains__.side_effect = lambda x: x in [IP, TCP]
    packet.__getitem__.side_effect = lambda x: fake_ip if x is IP else fake_tcp
    packet.haslayer.return_value = True
    return packet


# Crée un faux paquet ARP Spoofing (psrc == pdst)
def _make_arp_spoof_packet(ip="192.168.1.50", mac="AA:BB:CC:DD:EE:FF"):
    arp = MagicMock(psrc=ip, pdst=ip, hwsrc=mac)
    packet = MagicMock()
    packet.__contains__.side_effect = lambda x: x is ARP
    packet.__getitem__.side_effect = lambda x: arp
    return packet


# ---------- Fixture Capture patchée ----------

# Contexte pour créer une Capture sans interaction utilisateur
def _make_capture_ctx():
    return (
        patch("src.tp1.utils.capture.choose_interface", return_value="ens33"),
        patch("src.tp1.utils.capture.choose_duration", return_value=60),
        patch("src.tp1.utils.capture.choose_packet_count", return_value=0),
    )


# ---------- Tests de base ----------

def test_capture_init():
    p1, p2, p3 = _make_capture_ctx()
    with p1, p2, p3:
        capture = Capture()
        assert isinstance(capture.interface, str)
        assert capture.summary == ""
        assert isinstance(capture.packets, list)
        assert capture.duration == 60
        assert capture.packet_count == 0


def test_get_summary_empty():
    p1, p2, p3 = _make_capture_ctx()
    with p1, p2, p3:
        capture = Capture()
        capture.summary = "Test summary"
        assert capture.get_summary() == "Test summary"


# ---------- Tests capture mockée ----------

def test_capture_traffic_counts_protocols():
    p1, p2, p3 = _make_capture_ctx()
    with p1, p2, p3:
        with patch("src.tp1.utils.capture.sniff") as mock_sniff:
            with patch.object(Capture, "_display_progress"):

                def fake_sniff(iface, prn, **kwargs):
                    for _ in range(2):
                        prn(_make_tcp_packet())
                        prn(_make_udp_packet())

                mock_sniff.side_effect = fake_sniff
                capture = Capture()
                capture.capture_traffic()
            assert capture.interface == "ens33"
            assert capture.protocol_counter["TCP"] == 2
            assert capture.protocol_counter["UDP"] == 2
            capture.analyse()
            summary = capture.get_summary()
            assert "TCP" in summary
            assert "UDP" in summary
            assert "Interface: ens33" in summary
            assert "All traffic is legitimate" in summary
            analysis = capture.get_proto_analysis()
            assert analysis["TCP"]["status"] == "OK"
            assert analysis["UDP"]["status"] == "OK"


def test_capture_traffic_sqli_detection():
    p1, p2, p3 = _make_capture_ctx()
    with p1, p2, p3:
        with patch("src.tp1.utils.capture.sniff") as mock_sniff:
            with patch.object(Capture, "_display_progress"):

                def fake_sniff(iface, prn, **kwargs):
                    prn(_make_sqli_packet())

                mock_sniff.side_effect = fake_sniff
                capture = Capture()
                capture.capture_traffic()
            capture.analyse()
            summary = capture.get_summary()
            assert "[TCP] SQLi detected from 192.168.1.100" in summary
            assert capture.protocol_counter["TCP"] == 1


def test_capture_traffic_arp_spoof_detection():
    p1, p2, p3 = _make_capture_ctx()
    with p1, p2, p3:
        with patch("src.tp1.utils.capture.sniff") as mock_sniff:
            with patch.object(Capture, "_display_progress"):

                def fake_sniff(iface, prn, **kwargs):
                    prn(_make_arp_spoof_packet())

                mock_sniff.side_effect = fake_sniff
                capture = Capture()
                capture.capture_traffic()
            capture.analyse()
            summary = capture.get_summary()
            assert "[ARP] ARP Spoofing from MAC AA:BB:CC:DD:EE:FF / IP 192.168.1.50" in summary
            assert capture.protocol_counter["ARP"] == 1