# test_lib.py
from unittest.mock import patch
from src.tp1.utils.lib import hello_world, choose_interface, proto_name


def test_when_hello_world_then_return_hello_world():
    assert hello_world() == "hello world"


def test_when_choose_interface_then_return_user_choice():
    # Patch input pour simuler le choix utilisateur
    with patch("builtins.input", return_value="ens33"):
        result = choose_interface()
        assert result == "ens33"

    # Simuler entrée vide -> retourne eth0 par défaut
    with patch("builtins.input", return_value="ens33"):
        result = choose_interface()
        assert result == "ens33"


def test_proto_name_tcp_udp():
    assert proto_name(6) == "TCP"
    assert proto_name(17) == "UDP"
    assert proto_name("ARP") == "ARP"
    # Protocole inconnu
    assert proto_name(999) == "UNKNOWN"