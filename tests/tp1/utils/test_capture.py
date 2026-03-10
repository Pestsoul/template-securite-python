# test_capture.py
from unittest.mock import patch, MagicMock
from src.tp1.utils.capture import Capture
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP

# --------------------- Tests de base ---------------------

def test_capture_init():
    with patch("src.tp1.utils.capture.choose_interface", return_value="ens33"):
        with patch("src.tp1.utils.capture.choose_duration", return_value=60):
            capture = Capture()
            assert isinstance(capture.interface, str)
            assert capture.summary == ""
            assert isinstance(capture.packets, list)
            assert isinstance(capture.protocol_counter, dict)
            assert capture.duration == 60

def test_get_summary_empty():
    with patch("src.tp1.utils.capture.choose_interface", return_value="ens33"):
        with patch("src.tp1.utils.capture.choose_duration", return_value=60):
            capture = Capture()
            capture.summary = "Test summary"
            assert capture.get_summary() == "Test summary"

# --------------------- Tests capture mockée ---------------------

def test_capture_traffic_counts_protocols():
    with patch("src.tp1.utils.capture.choose_interface", return_value="ens33"):
        with patch("src.tp1.utils.capture.choose_duration", return_value=60):
          with patch("src.tp1.utils.capture.sniff") as mock_sniff:

            def fake_sniff(iface, prn, count, **kwargs):
                fake_ip_tcp = MagicMock()
                fake_ip_tcp.proto = 6
                fake_ip_tcp.src = "192.168.1.1"
                fake_ip_tcp.dst = "192.168.1.2"

                fake_packet_tcp = MagicMock()
                fake_packet_tcp.__contains__.side_effect = lambda x: x in [IP, TCP]
                fake_packet_tcp.__getitem__.side_effect = lambda x: fake_ip_tcp if x is IP else MagicMock()
                fake_packet_tcp.haslayer.return_value = True

                fake_ip_udp = MagicMock()
                fake_ip_udp.proto = 17
                fake_ip_udp.src = "10.0.0.1"
                fake_ip_udp.dst = "10.0.0.2"

                fake_packet_udp = MagicMock()
                fake_packet_udp.__contains__.side_effect = lambda x: x in [IP, UDP]
                fake_packet_udp.__getitem__.side_effect = lambda x: fake_ip_udp if x is IP else MagicMock()
                fake_packet_udp.haslayer.return_value = False

                for _ in range(count):
                    prn(fake_packet_tcp)
                    prn(fake_packet_udp)

            mock_sniff.side_effect = fake_sniff

            capture = Capture()
            capture.capture_traffic(packet_count=2)

            assert capture.interface == "ens33"
            assert capture.protocol_counter["TCP"] == 2
            assert capture.protocol_counter["UDP"] == 2

            capture.analyse()
            summary = capture.get_summary()
            assert "TCP" in summary
            assert "UDP" in summary
            assert "Interface: ens33" in summary
            assert "All traffic is legitimate" in summary

            # Vérification analyse par protocole
            analysis = capture.get_proto_analysis()
            assert "TCP" in analysis
            assert analysis["TCP"]["status"] == "OK"
            assert analysis["UDP"]["status"] == "OK"

# --------------------- Tests détection ---------------------

def test_capture_traffic_sqli_detection():
    with patch("src.tp1.utils.capture.choose_interface", return_value="ens33"):
        with patch("src.tp1.utils.capture.choose_duration", return_value=60):
          with patch("src.tp1.utils.capture.sniff") as mock_sniff:

            def fake_sniff(iface, prn, count, **kwargs):
                fake_ip = MagicMock()
                fake_ip.proto = 6
                fake_ip.src = "192.168.1.100"
                fake_ip.dst = "192.168.1.200"

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
            capture.analyse()
            summary = capture.get_summary()

            assert "[TCP] SQLi detected from 192.168.1.100" in summary
            assert capture.interface == "ens33"
            assert capture.protocol_counter["TCP"] == 1

def test_capture_traffic_arp_spoof_detection():
    with patch("src.tp1.utils.capture.choose_interface", return_value="ens33"):
        with patch("src.tp1.utils.capture.choose_duration", return_value=60):
          with patch("src.tp1.utils.capture.sniff") as mock_sniff:

            def fake_sniff(iface, prn, count, **kwargs):
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
            assert "[ARP] ARP Spoofing from MAC AA:BB:CC:DD:EE:FF / IP 192.168.1.50" in summary
            assert capture.protocol_counter["ARP"] == 1