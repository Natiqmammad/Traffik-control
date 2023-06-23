from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QMessageBox, QFileDialog, QVBoxLayout, QDialog, QLabel, QTableWidget, QTableWidgetItem
from PyQt5.QtGui import QTextCursor, QFont
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QSize
from PyQt5.QtWidgets import QWidget
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QHBoxLayout
from scapy.all import *




class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ağ İzleme Uygulaması by Natiqmammad")
        self.setWindowIcon(QIcon("C:/Users/magan/Downloads/icon.png"))
        self.setWindowFlags(Qt.WindowMinMaxButtonsHint)  # Minimize ve maksimize düğmelerini ekler
        self.resize(800, 600)  # Ekran boyutunu belirler
        self.setMinimumSize(QSize(600, 400))  # Minimum boyutu ayarlar
        self.setStyleSheet("""
    QMainWindow {
        background-color: #f2f2f2;
    }

    QPushButton {
        background-color: #ff4d4d;
        color: white;
        border: none;
        padding: 12px 24px;
        font-size: 16px;
        border-radius: 6px;
    }

    QPushButton:hover {
        background-color: #ff3333;
    }

    QPushButton:pressed {
        background-color: #ff1a1a;
    }

    QTableWidget {
        background-color: #f5f5f5;
        border: none;
        gridline-color: #ccc;
        selection-background-color: #e0e0e0;
        selection-color: #333;
    }

    QTableWidget QHeaderView::section {
        background-color: #ddd;
        border: none;
        padding: 10px;
        font-size: 14px;
    }

    QTableWidget QHeaderView::section:checked {
        background-color: #ff4d4d;
        color: white;
    }

    QTableWidget QTableWidgetItem {
        padding: 12px;
        border-bottom: 1px solid #ccc;
        font-size: 14px;
    }

    QTableWidget QTableWidgetItem:last-child {
        border-bottom: none;
    }

    QTextEdit {
        background-color: white;
        border: 1px solid #ccc;
        padding: 8px;
        color: #333;
        font-size: 14px;
    }

    QTextEdit:hover {
        border-color: #ff4d4d;
    }

    QDialog {
        background-color: #f2f2f2;
    }

    QLabel {
        font-size: 16px;
        color: #333;
    }
""")




        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        self.main_layout = QVBoxLayout(self.central_widget)

        self.top_layout = QHBoxLayout()
        self.main_layout.addLayout(self.top_layout)

        self.bottom_layout = QVBoxLayout()
        self.main_layout.addLayout(self.bottom_layout)

        self.start_button = QPushButton("Başlat")
        self.top_layout.addWidget(self.start_button)
        self.start_button.clicked.connect(self.start_capture)

        self.stop_button = QPushButton("Durdur")
        self.top_layout.addWidget(self.stop_button)
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)

        self.save_button = QPushButton("Kaydet")
        self.top_layout.addWidget(self.save_button)
        self.save_button.clicked.connect(self.save_traffic)

        self.edit_button = QPushButton("Düzenle")
        self.top_layout.addWidget(self.edit_button)
        self.edit_button.clicked.connect(self.edit_packet)
        self.edit_button.setEnabled(False)
        
        self.exit_button = QPushButton("Çıkış")  # Çıkış butonunu oluşturuyoruz
        self.top_layout.addWidget(self.exit_button)  # Butonu üst düzeninize ekliyoruz
        self.exit_button.clicked.connect(self.close)

        self.table_widget = QTableWidget()
        self.bottom_layout.addWidget(self.table_widget)
        self.table_widget.setColumnCount(2)
        self.table_widget.setHorizontalHeaderLabels(["No", "Özet"])
        self.table_widget.cellClicked.connect(self.packet_selected)

        self.text_edit = QTextEdit()
        self.bottom_layout.addWidget(self.text_edit)
        self.text_edit.setReadOnly(True)

        self.traffic_capture_thread = TrafficCaptureThread()
        self.traffic_capture_thread.packet_received.connect(self.packet_callback)

        self.save_path = None
        self.packet_list = []
        self.packet_count = 0

        self.update_ui()

    def resizeEvent(self, event):
        self.update_ui()

    def update_ui(self):
    # Ekran boyutuna göre düzeni günceller
        window_width = self.width()
        window_height = self.height()

        self.main_layout.setContentsMargins(int(window_width * 0.1), int(window_height * 0.05), int(window_width * 0.1), int(window_height * 0.05))

        self.main_layout.setSpacing(int(window_height * 0.02))

        button_width = window_width * 0.15
        button_height = window_height * 0.05
        font_size = window_height * 0.018

        self.start_button.setMinimumSize(QSize(int(button_width), int(button_height)))
        self.start_button.setFont(QFont("Arial", int(font_size)))

        self.stop_button.setMinimumSize(QSize(int(button_width), int(button_height)))
        self.stop_button.setFont(QFont("Arial", int(font_size)))

        self.save_button.setMinimumSize(QSize(int(button_width), int(button_height)))
        self.save_button.setFont(QFont("Arial", int(font_size)))

        self.edit_button.setMinimumSize(QSize(int(button_width), int(button_height)))
        self.edit_button.setFont(QFont("Arial", int(font_size)))

        table_width = window_width * 0.8
        table_height = window_height * 0.5
        self.table_widget.setMinimumSize(QSize(int(table_width), int(table_height)))

        text_edit_width = window_width * 0.8
        text_edit_height = window_height * 0.3
        self.text_edit.setMinimumSize(QSize(int(text_edit_width), int(text_edit_height)))
    

    def start_capture(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.edit_button.setEnabled(True)
        self.traffic_capture_thread.start()

    def stop_capture(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.edit_button.setEnabled(False)
        self.traffic_capture_thread.stop()
        self.traffic_capture_thread.wait()
        self.clear_traffic_table()

    def clear_traffic_table(self):
        self.table_widget.setRowCount(0)

    def save_traffic(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(self, "Kaydet", "", "PCAP Files (*.pcap)", options=options)
        if file_path:
            self.save_path = file_path
            QMessageBox.information(self, "Başarılı", f"Trafik kaydedildi: {file_path}")
        else:
            QMessageBox.warning(self, "Hata", "Kayıt dosyası seçilmedi.")

    def edit_packet(self):
        if self.current_packet:
            edit_window = TrafficEditWindow(self.current_packet)
            edit_window.exec_()

    def packet_callback(self, packet):
        self.current_packet = packet
        summary = packet.summary()
        self.text_edit.append(summary)
        self.analyze_packet(packet)

        self.packet_count += 1
        self.packet_list.append(packet)

        self.table_widget.setRowCount(self.packet_count)
        self.table_widget.setItem(self.packet_count - 1, 0, QTableWidgetItem(str(self.packet_count)))
        self.table_widget.setItem(self.packet_count - 1, 1, QTableWidgetItem(summary))

    def packet_selected(self, row, column):
        packet = self.packet_list[row]
        packet_details = packet.show(dump=True)
        new_window = PacketDetailsWindow(packet_details)
        new_window.exec_()

    def analyze_packet(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.text_edit.append("Kaynak IP: " + src_ip)
            self.text_edit.append("Hedef IP: " + dst_ip)
        else:
            self.text_edit.append("Pakette IP katmanı bulunamadı.")

class TrafficEditWindow(QDialog):
    def __init__(self, packet):
        super().__init__()
        self.setWindowTitle("Paket Düzenleme")
        self.setGeometry(100, 100, 400, 200)

        self.packet = packet

        if packet.haslayer(IP):
            layout = QVBoxLayout(self)

            src_label = QLabel("Kaynak IP:", self)
            layout.addWidget(src_label)

            self.src_ip_edit = QTextEdit(self)
            self.src_ip_edit.setPlainText(packet[IP].src)
            layout.addWidget(self.src_ip_edit)

            dst_label = QLabel("Hedef IP:", self)
            layout.addWidget(dst_label)

            self.dst_ip_edit = QTextEdit(self)
            self.dst_ip_edit.setPlainText(packet[IP].dst)
            layout.addWidget(self.dst_ip_edit)
        
            self.apply_button = QPushButton("Uygula", self)
            self.apply_button.clicked.connect(self.apply_changes)
            layout.addWidget(self.apply_button)
        else:
            QMessageBox.warning(self, "Hata", "Pakette IP katmanı bulunamadı.")

    def apply_changes(self):
        new_src_ip = self.src_ip_edit.toPlainText()
        new_dst_ip = self.dst_ip_edit.toPlainText()

        self.packet[IP].src = new_src_ip
        self.packet[IP].dst = new_dst_ip

        self.close()

class TrafficCaptureThread(QThread):
    packet_received = pyqtSignal(object)

    def __init__(self, save_path=None):
        super().__init__()
        self.save_path = save_path

    def run(self):
        if self.save_path:
            sniff(prn=self.packet_callback, store=0)
        else:
            sniff(prn=self.packet_callback)

    def packet_callback(self, packet):
        self.packet_received.emit(packet)
        if self.save_path:
            wrpcap(self.save_path, packet, append=True)

class PacketDetailsWindow(QDialog):
    def __init__(self, packet_details):
        super().__init__()
        self.setWindowTitle("Paket Detayları")
        self.setGeometry(100, 100, 800, 600)

        layout = QVBoxLayout(self)

        details_label = QLabel("Paket Detayları:", self)
        layout.addWidget(details_label)

        self.details_text_edit = QTextEdit(self)
        self.details_text_edit.setPlainText(packet_details)
        self.details_text_edit.setReadOnly(True)
        layout.addWidget(self.details_text_edit)

if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()
