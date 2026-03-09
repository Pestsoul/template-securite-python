# lib.py

# ------------------------ Fonctions de base ------------------------

def hello_world() -> str:
    """
    Hello world function
    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice.
    If empty input, return default 'ens33'
    """
    try:
        iface = input("Choose interface (default ens33): ").strip()
        return iface if iface else "ens33"
    except Exception:
        return "ens33"


# ------------------------ Gestion des protocoles ------------------------

# Mapping des protocoles IP connus
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    # ajouter d'autres protocoles si nécessaire
}

def proto_name(proto) -> str:
    """
    Convertit un numéro de protocole en nom lisible.
    Si le protocole est inconnu, renvoie "UNKNOWN".
    Gère également le cas spécial pour ARP.
    """
    try:
        proto_int = int(proto)
        return PROTO_MAP.get(proto_int, "UNKNOWN")
    except (ValueError, TypeError):
        if proto == "ARP":
            return "ARP"
        return "UNKNOWN"