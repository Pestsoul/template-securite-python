# test_lib.py
from unittest.mock import patch
from src.tp1.utils.lib import hello_world, choose_interface, choose_duration, choose_packet_count, proto_name


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


def test_choose_duration_hours():
    with patch("builtins.input", return_value="1h"):
        assert choose_duration() == 3600

def test_choose_duration_minutes_suffix():
    with patch("builtins.input", return_value="30min"):
        assert choose_duration() == 1800

def test_choose_duration_minutes_short():
    with patch("builtins.input", return_value="30m"):
        assert choose_duration() == 1800

def test_choose_duration_seconds():
    with patch("builtins.input", return_value="45s"):
        assert choose_duration() == 45

def test_choose_duration_no_suffix():
    with patch("builtins.input", return_value="2"):
        assert choose_duration() == 120  # sans suffixe = minutes

def test_choose_duration_default():
    with patch("builtins.input", return_value=""):
        assert choose_duration() == 60  # 1 minute par défaut

def test_choose_duration_invalid():
    with patch("builtins.input", return_value="abc"):
        assert choose_duration() == 60  # fallback 1 minute


def test_choose_packet_count_value():
    with patch("builtins.input", return_value="50"):
        assert choose_packet_count() == 50

def test_choose_packet_count_unlimited():
    with patch("builtins.input", return_value="0"):
        assert choose_packet_count() == 0

def test_choose_packet_count_default():
    with patch("builtins.input", return_value=""):
        assert choose_packet_count() == 0

def test_choose_packet_count_invalid():
    with patch("builtins.input", return_value="abc"):
        assert choose_packet_count() == 0