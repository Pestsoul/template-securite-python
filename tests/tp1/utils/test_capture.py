# test_capture.py
from unittest.mock import patch, MagicMock
from src.tp1.utils.capture import Capture
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP

# --------------------- Tests de base ---------------------

def test_capture_init():
    capture = Capture()
    assert isinstance(capture.interface, str)
    assert capture.summary == ""
    assert isinstance(capture.packets, list)
    assert isinstance(capture.protocol_counter, dict)

def test_get_summary_empty():
    capture = Capture()
    capture.summary = "Test summary"
    assert capture.get_summary() == "Test summary"

# --------------------- Tests capture mockée ---------------------

def test_capture_traffic_counts_protocols():
    # Patch choose_interface avant création de Capture
    with patch("src.tp1.utils.capture.choose_interface", return_value="ens33"):
        with patch("src.tp1.utils.capture.sniff") as mock_sniff:

            def fake_sniff(iface, prn, count):
                fake_packet_tcp = MagicMock()
                fake_packet_tcp.__contains__.side_effect = lambda x: x in [IP, TCP]
                fake_packet_tcp.__getitem__.side_effect = lambda x: MagicMock(proto=6) if x is IP else MagicMock()
                fake_packet_tcp.haslayer.return_value = True

                fake_packet_udp = MagicMock()
                fake_packet_udp.__contains__.side_effect = lambda x: x in [IP, UDP]
                fake_packet_udp.__getitem__.side_effect = lambda x: MagicMock(proto=17) if x is IP else MagicMock()
                fake_packet_udp.haslayer.return_value = False

                for _ in range(count):
                    prn(fake_packet_tcp)
                    prn(fake_packet_udp)

            mock_sniff.side_effect = fake_sniff

            capture = Capture()
            capture.capture_traffic(packet_count=2)

            # Vérifications
            assert capture.interface == "ens33"
            # On a 2 paquets TCP et 2 paquets UDP
            assert capture.protocol_counter["TCP"] == 2
            assert capture.protocol_counter["UDP"] == 2

            capture.analyse()
            summary = capture.get_summary()
            assert "TCP: 2" in summary
            assert "UDP: 2" in summary
            assert "Interface: ens33" in summary
            assert "All traffic is legitimate" in summary

# --------------------- Tests détection ---------------------

def test_capture_traffic_sqli_detection():
    with patch("src.tp1.utils.capture.choose_interface", return_value="ens33"):
        with patch("src.tp1.utils.capture.sniff") as mock_sniff:

            def fake_sniff(iface, prn, count):
                # IP layer mock avec src et proto
                fake_ip = MagicMock()
                fake_ip.proto = 6
                fake_ip.src = "192.168.1.100"

                # TCP layer mock avec payload SQLi
                fake_tcp = MagicMock()
                fake_tcp.payload = b"SELECT * FROM users"

                sqli_packet = MagicMock()
                sqli_packet.__contains__.side_effect = lambda x: x in [IP, TCP]
                sqli_packet.__getitem__.side_effect = lambda x: fake_ip if x is IP else fake_tcp
                sqli_packet.haslayer.return_value = True

                for _ in range(count):
                    prn(sqli_packet)

            mock_sniff.side_effect = fake_sniff

            capture = Capture()
            capture.capture_traffic(packet_count=1)
            capture.analyse("tcp")
            summary = capture.get_summary()

            # Vérifications
            assert "SQLi detected from 192.168.1.100" in summary
            assert capture.interface == "ens33"
            assert capture.protocol_counter["TCP"] == 1

def test_capture_traffic_arp_spoof_detection():
    with patch("src.tp1.utils.capture.choose_interface", return_value="ens33"):
        with patch("src.tp1.utils.capture.sniff") as mock_sniff:

            def fake_sniff(iface, prn, count):
                arp_packet = MagicMock()
                arp_packet.__contains__.side_effect = lambda x: x is ARP
                arp_packet.__getitem__.side_effect = lambda x: MagicMock(
                    psrc="192.168.1.50",
                    pdst="192.168.1.50",
                    hwsrc="AA:BB:CC:DD:EE:FF"
                )
                prn(arp_packet)

            mock_sniff.side_effect = fake_sniff

            capture = Capture()
            capture.capture_traffic(packet_count=1)
            capture.analyse()
            summary = capture.get_summary()
            assert "ARP spoofing detected from AA:BB:CC:DD:EE:FF" in summary
            assert capture.protocol_counter["ARP"] == 1
