# capture.py
from collections import defaultdict
import threading
import time
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
from tp1.utils.lib import choose_interface, choose_duration, choose_packet_count, proto_name
from tp1.utils.config import logger


class Capture:
    # Initialisation de la classe avec les attributs nécessaires à la capture et à l'analyse
    def __init__(self) -> None:
        self.interface = choose_interface() or "ens33"
        self.duration = choose_duration()
        self.packet_count = choose_packet_count()  # 0 = illimité
        self.packets = []
        self.protocol_counter = defaultdict(int)
        self.ip_packet_counter = defaultdict(int)
        self.ip_proto_map = defaultdict(set)
        self.ip_proto_counter = defaultdict(lambda: defaultdict(int))
        self.proto_suspicious = defaultdict(list)
        self.summary = ""
        self.suspicious = []

    # Traite un paquet IP : identifie le protocole et trace src/dst
    def _handle_ip(self, packet) -> None:
        proto = proto_name(packet[IP].proto)
        self.protocol_counter[proto] += 1
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        for ip in (src_ip, dst_ip):
            self.ip_packet_counter[ip] += 1
            self.ip_proto_map[ip].add(proto)
            self.ip_proto_counter[ip][proto] += 1

    # Traite un paquet ARP : trace src/dst
    def _handle_arp(self, packet) -> None:
        self.protocol_counter["ARP"] += 1
        src_ip, dst_ip = packet[ARP].psrc, packet[ARP].pdst
        for ip in (src_ip, dst_ip):
            self.ip_packet_counter[ip] += 1
            self.ip_proto_map[ip].add("ARP")
            self.ip_proto_counter[ip]["ARP"] += 1

    # Détecte une injection SQL dans le payload TCP
    def _detect_sqli(self, packet) -> None:
        if not (hasattr(packet, "haslayer") and packet.haslayer(TCP)):
            return
        payload = getattr(packet[TCP], "payload", None)
        if payload and b"SELECT" in str(payload).encode():
            src = packet[IP].src if IP in packet else "Unknown"
            alert = f"[TCP] SQLi detected from {src}"
            self.suspicious.append(alert)
            self.proto_suspicious["TCP"].append(alert)

    # Détecte un ARP Spoofing : IP source == IP destination
    def _detect_arp_spoof(self, packet) -> None:
        if ARP in packet and packet[ARP].psrc == packet[ARP].pdst:
            alert = f"[ARP] ARP Spoofing from MAC {packet[ARP].hwsrc} / IP {packet[ARP].psrc}"
            self.suspicious.append(alert)
            self.proto_suspicious["ARP"].append(alert)

    # Traite chaque paquet capturé : routage + détections
    def _packet_handler(self, packet) -> None:
        self.packets.append(packet)
        if IP in packet:
            self._handle_ip(packet)
        elif ARP in packet:
            self._handle_arp(packet)
        else:
            self.protocol_counter["UNKNOWN"] += 1
        self._detect_sqli(packet)
        self._detect_arp_spoof(packet)

    # Affiche le temps restant et le nombre de paquets en temps réel
    def _display_progress(self, stop_event: threading.Event) -> None:
        start = time.time()
        while not stop_event.is_set():
            elapsed = time.time() - start
            remaining = max(0.0, float(self.duration) - elapsed)
            pkt_count = len(self.packets)
            if remaining >= 3600:
                time_str = f"{int(remaining // 3600)}h{int((remaining % 3600) // 60)}min"
            elif remaining >= 60:
                time_str = f"{int(remaining // 60)}min{int(remaining % 60)}s"
            else:
                time_str = f"{int(remaining)}s"
            pkt_str = f"{pkt_count}/{self.packet_count}" if self.packet_count > 0 else str(pkt_count)
            print(f"\rTemps restant: {time_str}  |  {pkt_str} packets   ", end="", flush=True)
            time.sleep(0.5)
        print()

    # Capture le trafic réseau : s'arrête à la durée OU au nombre de paquets max
    def capture_traffic(self) -> None:
        count_str = f"max {self.packet_count} packets" if self.packet_count > 0 else "unlimited packets"
        logger.info(f"Capture sur {self.interface} ({count_str})")
        stop_event = threading.Event()
        thread = threading.Thread(target=self._display_progress, args=(stop_event,), daemon=True)
        thread.start()
        try:
            sniff(iface=self.interface, prn=self._packet_handler, count=self.packet_count, timeout=self.duration)
        finally:
            stop_event.set()
            thread.join()

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
        summary += f"Total packets capturé : {len(self.packets)}\n\n"
        summary += "Protocols detecté :\n"
        summary += f"{'Protocol':<12} {'Packets':>8}\n"
        summary += "-" * 22 + "\n"
        for proto, count in self.sort_network_protocols().items():
            summary += f"{proto:<12} {count:>8}\n"
        summary += "\nPackets par IP address:\n"
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