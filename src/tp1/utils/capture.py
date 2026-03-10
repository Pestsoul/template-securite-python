# capture.py
from collections import defaultdict
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import ARP
from tp1.utils.lib import choose_interface, choose_duration, proto_name
from tp1.utils.config import logger


class Capture:
    # Initialisation de la classe avec les attributs nécessaires à la capture et à l'analyse
    def __init__(self) -> None:
        self.interface = choose_interface() or "ens33"
        self.duration = choose_duration()
        self.packets = []
        self.protocol_counter = defaultdict(int)             # {proto: nb_paquets}
        self.ip_packet_counter = defaultdict(int)            # {ip: total_packets}
        self.ip_proto_map = defaultdict(set)                 # {ip: set of protocols}
        self.ip_proto_counter = defaultdict(lambda: defaultdict(int))  # {ip: {proto: count}}
        self.proto_suspicious = defaultdict(list)            # {proto: [alerts]}
        self.summary = ""
        self.suspicious = []

    # Capture le trafic réseau sur l'interface choisie pendant la durée définie
    def capture_traffic(self, packet_count: int = 100) -> None:
        if self.duration >= 3600:
            duration_str = f"{self.duration // 3600}h"
        elif self.duration >= 60:
            duration_str = f"{self.duration // 60}min"
        else:
            duration_str = f"{self.duration}s"
        logger.info(f"Capturing traffic from interface {self.interface} for {duration_str}")

        def packet_handler(packet):
            self.packets.append(packet)

            # Paquet IP : on récupère le protocole et on trace src/dst
            if IP in packet:
                proto_num = packet[IP].proto
                proto = proto_name(proto_num)
                self.protocol_counter[proto] += 1

                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                self.ip_packet_counter[src_ip] += 1
                self.ip_packet_counter[dst_ip] += 1
                self.ip_proto_map[src_ip].add(proto)
                self.ip_proto_map[dst_ip].add(proto)
                self.ip_proto_counter[src_ip][proto] += 1
                self.ip_proto_counter[dst_ip][proto] += 1

            # Paquet ARP : on trace les IPs source et destination
            elif ARP in packet:
                self.protocol_counter["ARP"] += 1
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
                self.ip_packet_counter[src_ip] += 1
                self.ip_packet_counter[dst_ip] += 1
                self.ip_proto_map[src_ip].add("ARP")
                self.ip_proto_map[dst_ip].add("ARP")
                self.ip_proto_counter[src_ip]["ARP"] += 1
                self.ip_proto_counter[dst_ip]["ARP"] += 1

            # Paquet non reconnu (ni IP ni ARP)
            else:
                self.protocol_counter["UNKNOWN"] += 1

            # Détection ICMP : compté séparément car inclus dans IP
            if ICMP in packet:
                self.protocol_counter["ICMP"] += 1
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    self.ip_packet_counter[src_ip] += 1
                    self.ip_packet_counter[dst_ip] += 1
                    self.ip_proto_map[src_ip].add("ICMP")
                    self.ip_proto_map[dst_ip].add("ICMP")
                    self.ip_proto_counter[src_ip]["ICMP"] += 1
                    self.ip_proto_counter[dst_ip]["ICMP"] += 1

            # Détection SQLi : on cherche SELECT dans le payload TCP
            if hasattr(packet, "haslayer") and packet.haslayer(TCP):
                payload = getattr(packet[TCP], "payload", None)
                if payload and b"SELECT" in str(payload).encode():
                    src = packet[IP].src if IP in packet else "Unknown"
                    alert = f"[TCP] SQLi detected from {src}"
                    self.suspicious.append(alert)
                    self.proto_suspicious["TCP"].append(alert)

            # Détection ARP Spoofing : l'IP source et destination sont identiques
            if ARP in packet:
                if packet[ARP].psrc == packet[ARP].pdst:
                    alert = f"[ARP] ARP Spoofing from MAC {packet[ARP].hwsrc} / IP {packet[ARP].psrc}"
                    self.suspicious.append(alert)
                    self.proto_suspicious["ARP"].append(alert)

        sniff(iface=self.interface, prn=packet_handler, count=packet_count, timeout=self.duration)

    # Retourne les protocoles triés par nombre de paquets décroissant
    def sort_network_protocols(self) -> dict:
        return dict(sorted(self.protocol_counter.items(), key=lambda x: x[1], reverse=True))

    # Retourne tous les protocoles capturés avec leur nombre de paquets
    def get_all_protocols(self) -> dict:
        return dict(self.protocol_counter)

    # Lance l'analyse et génère le résumé textuel
    def analyse(self) -> None:
        logger.debug(f"All protocols: {self.get_all_protocols()}")
        logger.debug(f"Sorted protocols: {self.sort_network_protocols()}")
        self.summary = self._gen_summary()

    # Retourne le résumé généré par analyse()
    def get_summary(self) -> str:
        return self.summary

    # Retourne l'analyse par protocole avec statut légitime ou suspect
    def get_proto_analysis(self) -> dict:
        analysis = {}
        for proto, count in self.protocol_counter.items():
            alerts = self.proto_suspicious.get(proto, [])
            analysis[proto] = {
                "count": count,
                "status": "SUSPICIOUS" if alerts else "OK",
                "alerts": alerts,
            }
        return analysis

    # Génère le résumé textuel complet : protocoles, IPs, et analyse du trafic
    def _gen_summary(self) -> str:
        summary = "=== IDS SUMMARY ===\n\n"
        summary += f"Interface: {self.interface}\n"
        summary += f"Total packets captured: {len(self.packets)}\n\n"

        summary += "Protocols detected:\n"
        summary += f"{'Protocol':<12} {'Packets':>8}\n"
        summary += "-" * 22 + "\n"
        for proto, count in self.sort_network_protocols().items():
            summary += f"{proto:<12} {count:>8}\n"

        summary += "\nPackets per IP address:\n"
        summary += f"{'IP Address':<20} {'Packets':>8}  {'Protocols'}\n"
        summary += "-" * 50 + "\n"
        sorted_ips = sorted(self.ip_packet_counter.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ips:
            proto_details = ", ".join(
                f"{p}: {c}" for p, c in sorted(self.ip_proto_counter.get(ip, {}).items())
            )
            summary += f"{ip:<20} {count:>8}  {proto_details}\n"

        summary += "\nTraffic analysis:\n"
        if not self.suspicious:
            summary += "All traffic is legitimate.\n"
        else:
            summary += "\n".join(self.suspicious) + "\n"

        return summary