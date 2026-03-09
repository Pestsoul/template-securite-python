from unittest.mock import MagicMock, patch, mock_open
from src.tp1.utils.report import Report

def test_report_init():
    report = Report(MagicMock(), "test.pdf", "Test summary")
    assert report.title == "TITRE DU RAPPORT\n"
    assert report.array == ""
    assert report.graph == ""

def test_concat_report():
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.title = "Test Title"
    report.array = "Array"
    report.graph = "Graph"
    result = report.concat_report()
    assert result == "Test TitleTest summary\nArray\nGraph\n"

def test_save():
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.title = "Test Title"
    with patch("builtins.open", mock_open()) as mock_file:
        report.save("test.pdf")
        mock_file().write.assert_called_once_with("Test TitleTest summary\n")

def test_generate():
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.generate("graph")
    assert report.graph == "network_graph.svg"
    report.generate("array")
    assert report.array == "protocol_table.csv"