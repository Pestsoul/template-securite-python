# report.py
import csv
import os
import tempfile
import pygal
from PIL import Image, ImageDraw
from fpdf import FPDF
from fpdf.enums import XPos, YPos
from src.tp1.utils.capture import Capture


class Report:
    # Initialisation du rapport avec la capture, le nom de fichier et le résumé
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "TITRE DU RAPPORT\n"
        self.summary = summary
        self.array = ""
        self.graph = ""

    # ---------- CSV ----------

    # Génère un fichier CSV avec 3 sections : protocoles, IPs, attaques
    def _generate_csv(self) -> str:
        csv_filename = "protocol_table.csv"
        with open(csv_filename, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["=== PROTOCOL TABLE ==="])
            writer.writerow(["Protocol", "Packet count"])
            for proto, count in self.capture.protocol_counter.items():
                writer.writerow([proto, count])
            writer.writerow([])
            writer.writerow(["=== IP TABLE ==="])
            writer.writerow(["IP Address", "Packet count", "Protocols"])
            sorted_ips = sorted(self.capture.ip_packet_counter.items(), key=lambda x: x[1], reverse=True)
            for ip, count in sorted_ips:
                proto_details = ", ".join(
                    f"{p}: {c}" for p, c in sorted(self.capture.ip_proto_counter.get(ip, {}).items())
                )
                writer.writerow([ip, count, proto_details])
            writer.writerow([])
            writer.writerow(["=== ATTACKS DETECTED ==="])
            if not self.capture.suspicious:
                writer.writerow(["No attacks detected."])
            else:
                for alert in self.capture.suspicious:
                    writer.writerow([alert])
        return csv_filename

    # ---------- GRAPH (pygal) ----------

    # Génère un graphique SVG interactif des protocoles avec pygal
    def _generate_graph(self) -> str:
        graph_filename = "network_graph.svg"
        bar_chart = pygal.Bar()
        bar_chart.title = "Network Traffic per Protocol"
        for proto, count in self.capture.protocol_counter.items():
            bar_chart.add(proto, count)
        bar_chart.render_to_file(graph_filename)
        return graph_filename

    # ---------- PDF helpers ----------

    # Génère l'en-tête du PDF : titre et métadonnées interface/paquets
    def _pdf_header(self, pdf: FPDF) -> None:
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "RAPPORT IDS - ANALYSE RESEAU", align="C",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)
        pdf.set_font("Helvetica", size=10)
        for line in self.summary.split("\n"):
            line = line.strip()
            if line.startswith("Interface:") or line.startswith("Total packets"):
                pdf.cell(0, 6, line, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(5)

    # Génère le bar chart PNG avec Pillow et l'insère dans le PDF
    def _pdf_chart(self, pdf: FPDF) -> None:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Graphique du trafic reseau", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        tmp_png = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        tmp_png.close()
        try:
            self._draw_bar_chart(tmp_png.name)
            pdf.image(tmp_png.name, x=15, w=175)
        finally:
            os.unlink(tmp_png.name)
        pdf.ln(5)

    # Dessine le bar chart avec Pillow et sauvegarde en PNG
    def _draw_bar_chart(self, path: str) -> None:
        protocols = list(self.capture.protocol_counter.keys())
        counts = list(self.capture.protocol_counter.values())
        max_count = max(counts) if counts else 1
        colors_hex = ["#F44336", "#3F51B5", "#009688", "#FFC107", "#FF5722"]
        n = len(protocols) if protocols else 1
        margin_left, margin_top, margin_bottom = 60, 50, 50
        W = max(750, margin_left + 20 + n * 80)
        H = 350
        img = Image.new("RGB", (W, H), "white")
        draw = ImageDraw.Draw(img)
        chart_w = W - margin_left - 20
        chart_h = H - margin_top - margin_bottom
        bar_slot = chart_w // n
        bar_w = max(bar_slot - 20, 20)
        draw.text((W // 2, 15), "Network Traffic per Protocol", fill="black", anchor="mt")
        draw.line([margin_left, margin_top, margin_left, margin_top + chart_h], fill="black", width=2)
        draw.line([margin_left, margin_top + chart_h, W - 20, margin_top + chart_h], fill="black", width=2)
        for i, (proto, count) in enumerate(zip(protocols, counts)):
            bar_h = int((count / max_count) * chart_h)
            x = margin_left + i * bar_slot + 10
            y_top = margin_top + chart_h - bar_h
            y_bot = margin_top + chart_h
            color = colors_hex[i % len(colors_hex)]
            draw.rectangle([x, y_top, x + bar_w, y_bot], fill=color)
            draw.text((x + bar_w // 2, y_top - 5), str(count), fill="black", anchor="mb")
            draw.text((x + bar_w // 2, y_bot + 8), proto, fill="black", anchor="mt")
        img.save(path)

    # Insère le tableau des protocoles dans le PDF
    def _pdf_protocol_table(self, pdf: FPDF) -> None:
        if not self.capture.protocol_counter:
            return
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Tableau des protocoles", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(80, 7, "Protocole", border=1)
        pdf.cell(80, 7, "Nombre de paquets", border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", size=10)
        for proto, count in sorted(self.capture.protocol_counter.items(), key=lambda x: x[1], reverse=True):
            pdf.cell(80, 7, str(proto), border=1)
            pdf.cell(80, 7, str(count), border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(5)

    # Insère le tableau des IPs avec détail des protocoles dans le PDF
    def _pdf_ip_table(self, pdf: FPDF) -> None:
        if not self.capture.ip_packet_counter:
            return
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Paquets par adresse IP", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(60, 7, "Adresse IP", border=1)
        pdf.cell(30, 7, "Total", border=1)
        pdf.cell(90, 7, "Detail par protocole", border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", size=10)
        sorted_ips = sorted(self.capture.ip_packet_counter.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ips:
            proto_details = ", ".join(
                f"{p}: {c}" for p, c in sorted(self.capture.ip_proto_counter.get(ip, {}).items())
            )
            pdf.cell(60, 7, str(ip), border=1)
            pdf.cell(30, 7, str(count), border=1)
            pdf.cell(90, 7, proto_details, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(5)

    # Insère l'analyse par protocole (vert=légitime, rouge=suspect) dans le PDF
    def _pdf_proto_analysis(self, pdf: FPDF) -> None:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Analyse par protocole", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        proto_analysis = self.capture.get_proto_analysis()
        for proto, info in sorted(proto_analysis.items()):
            pdf.set_font("Helvetica", "B", 11)
            is_suspect = info["status"] == "SUSPICIOUS"
            pdf.set_text_color(*(200, 0, 0) if is_suspect else (0, 150, 0))
            status_label = "SUSPECT" if is_suspect else "LEGITIME"
            pdf.cell(0, 8, f"{proto}  ({info['count']} paquets) - {status_label}",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", size=10)
            if info["alerts"]:
                for alert in info["alerts"]:
                    pdf.set_text_color(200, 0, 0)
                    pdf.cell(0, 6, f"  {alert}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
            else:
                pdf.set_text_color(0, 150, 0)
                pdf.cell(0, 6, "  Aucune activite suspecte detectee.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
        if not proto_analysis:
            pdf.set_font("Helvetica", size=10)
            pdf.set_text_color(0, 150, 0)
            pdf.cell(0, 7, "Tout le trafic est legitime.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)

    # Orchestre la génération complète du PDF en appelant chaque section
    def _generate_pdf(self, filename: str) -> None:
        pdf = FPDF()
        pdf.add_page()
        self._pdf_header(pdf)
        self._pdf_chart(pdf)
        self._pdf_protocol_table(pdf)
        self._pdf_ip_table(pdf)
        self._pdf_proto_analysis(pdf)
        pdf.output(filename)

    # ---------- REPORT ----------

    # Concatène titre, résumé, tableau et graphe en une seule chaîne
    def concat_report(self) -> str:
        content = self.title + self.summary + "\n"
        if self.array:
            content += self.array + "\n"
        if self.graph:
            content += self.graph + "\n"
        return content

    # Sauvegarde le rapport en PDF ou en fichier texte selon l'extension
    def save(self, filename: str = None) -> None:
        filename = filename or self.filename
        if filename.endswith(".pdf"):
            self._generate_pdf(filename)
        else:
            with open(filename, "w") as report:
                report.write(self.concat_report())

    # Génère le graphique SVG ou le fichier CSV selon le paramètre
    def generate(self, param: str) -> None:
        if param == "graph":
            self.graph = self._generate_graph()
        elif param == "array":
            self.array = self._generate_csv()