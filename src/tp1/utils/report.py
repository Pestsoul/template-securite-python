# report.py
import csv
import pygal
from src.tp1.utils.capture import Capture


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "TITRE DU RAPPORT\n"
        self.summary = summary
        self.array = ""
        self.graph = ""

    # ---------- CSV ----------

    def _generate_csv(self) -> str:
        csv_filename = "protocol_table.csv"
        with open(csv_filename, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Protocol", "Packet count"])
            for proto, count in self.capture.protocol_counter.items():
                writer.writerow([proto, count])
        return csv_filename

    # ---------- GRAPH (pygal) ----------

    def _generate_graph(self) -> str:
        graph_filename = "network_graph.svg"

        bar_chart = pygal.Bar()
        bar_chart.title = "Network Traffic per Protocol"

        for proto, count in self.capture.protocol_counter.items():
            bar_chart.add(proto, count)

        bar_chart.render_to_file(graph_filename)
        return graph_filename

    # ---------- REPORT ----------

    def concat_report(self) -> str:
        content = self.title + self.summary + "\n"
        if self.array:
            content += self.array + "\n"
        if self.graph:
            content += self.graph + "\n"
        return content

    def save(self, filename: str = None) -> None:
        filename = filename or self.filename
        with open(filename, "w") as report:
            report.write(self.concat_report())

    def generate(self, param: str) -> None:
        if param == "graph":
            self.graph = self._generate_graph()
        elif param == "array":
            self.array = self._generate_csv()