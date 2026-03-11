# lib.py

# ------------------------ Fonctions de base ------------------------

# Fonction de test hello world
def hello_world() -> str:
    return "hello world"


# Demande à l'utilisateur de choisir une interface réseau, ens33 par défaut
def choose_interface() -> str:
    try:
        iface = input("Choix interface (default ens33): ").strip()
        return iface if iface else "ens33"
    except Exception:
        return "ens33"


# ------------------------ Gestion de la durée ------------------------

# Demande à l'utilisateur la durée de capture avec support des suffixes h/min/m/s
def choose_duration() -> int:
    try:
        val = input("Capture duration (ex: 1h, 30min, 45s - default 1min): ").strip().lower()
        if not val:
            return 60
        if val.endswith("h"):
            return int(val[:-1]) * 3600
        elif val.endswith("min"):
            return int(val[:-3]) * 60
        elif val.endswith("m"):
            return int(val[:-1]) * 60
        elif val.endswith("s"):
            return int(val[:-1])
        else:
            return int(val) * 60  # sans suffixe = minutes par défaut
    except (ValueError, Exception):
        return 60


# ------------------------ Gestion des protocoles ------------------------

# Mapping des numéros de protocole IP vers leur nom lisible
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

# Demande à l'utilisateur le nombre maximum de paquets à capturer, 0 = illimité
def choose_packet_count() -> int:
    try:
        val = input("Max packets à capturé (0 = unlimited, default 0): ").strip()
        return int(val) if val else 0
    except (ValueError, Exception):
        return 0


# Convertit un numéro de protocole IP en nom lisible, retourne UNKNOWN si inconnu
def proto_name(proto) -> str:
    try:
        proto_int = int(proto)
        return PROTO_MAP.get(proto_int, "UNKNOWN")
    except (ValueError, TypeError):
        if proto == "ARP":
            return "ARP"
        return "UNKNOWN"