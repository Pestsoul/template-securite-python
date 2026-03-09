# capture.py
from collections import defaultdict
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
from tp1.utils.lib import choose_interface, proto_name
from tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface() or "ens33"
        self.packets = []
        self.protocol_counter = defaultdict(int)
        self.summary = ""
        self.suspicious = []

    def capture_traffic(self, packet_count: int = 100) -> None:
        """
        Capture network traffic from an interface.
        """
        logger.info(f"Capturing traffic from interface {self.interface}")

        def packet_handler(packet):
            self.packets.append(packet)

            # Compter protocol avec nom lisible
            if IP in packet:
                proto_num = packet[IP].proto
                proto = proto_name(proto_num)  # TCP/UDP/ICMP
                self.protocol_counter[proto] += 1
            elif ARP in packet:
                self.protocol_counter["ARP"] += 1

            # Détection SQLi (exemple simple)
            if hasattr(packet, "haslayer") and packet.haslayer(TCP):
                payload = getattr(packet[TCP], "payload", None)
                if payload and b"SELECT" in str(payload).encode():
                    src = packet[IP].src if IP in packet else "Unknown"
                    self.suspicious.append(f"SQLi detected from {src}")

            # Détection ARP spoofing simple
            if ARP in packet:
                if packet[ARP].psrc == packet[ARP].pdst:
                    self.suspicious.append(f"ARP spoofing detected from {packet[ARP].hwsrc}")

        sniff(iface=self.interface, prn=packet_handler, count=packet_count)

    def sort_network_protocols(self) -> dict:
        """
        Sort protocols by number of packets descending.
        """
        return dict(sorted(self.protocol_counter.items(), key=lambda x: x[1], reverse=True))

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number.
        """
        return dict(self.protocol_counter)

    def analyse(self, protocols: str = "") -> None:
        """
        Analyse all captured data and update summary.
        """
        logger.debug(f"All protocols: {self.get_all_protocols()}")
        logger.debug(f"Sorted protocols: {self.sort_network_protocols()}")
        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary.
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary with readable protocol names and traffic analysis.
        """
        summary = "=== IDS SUMMARY ===\n\n"
        summary += f"Interface: {self.interface}\n"
        summary += f"Total packets captured: {len(self.packets)}\n\n"

        # Protocols detected
        summary += "Protocols detected:\n"
        for proto, count in self.protocol_counter.items():
            summary += f"{proto}: {count}\n"

        # Traffic analysis
        summary += "\nTraffic analysis:\n"
        if not self.suspicious:
            summary += "All traffic is legitimate.\n"
        else:
            summary += "\n".join(self.suspicious) + "\n"

        return summary
