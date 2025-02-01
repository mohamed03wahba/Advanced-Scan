import sys
import subprocess
import re
import shutil
import requests
import ctypes
import webbrowser
import json
from PyQt6.QtWidgets import (QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QTextEdit, 
                             QVBoxLayout, QWidget, QMessageBox, QFileDialog, QCheckBox)
from PyQt6.QtCore import QThread, pyqtSignal
from datetime import datetime
from cvss import CVSS3  # Import CVSS3 class

# Date for file naming
stringtoday = datetime.today().strftime('%Y-%m-%d')

class VulnersScanThread(QThread):
    output_signal = pyqtSignal(str)  # Signal to send the scan output to the main thread
    error_signal = pyqtSignal(str)  # Signal for error messages

    def __init__(self, target_ip, scan_speed, ports, os_detection):
        super().__init__()
        self.target_ip = target_ip
        self.scan_speed = scan_speed
        self.ports = ports
        self.os_detection = os_detection

    def run(self):
        if not shutil.which("nmap"):
            self.error_signal.emit("Nmap is not installed. Please install it first.")
            return
        try:
            # Base command
            command = f"nmap --script vulners -sV -T{self.scan_speed} "
            
            # Add OS detection if required
            if self.os_detection:
                command += " -O"
            
            # Add ports if specified
            if self.ports:
                command += f" -p {self.ports}"
            
            # Add target IP/range
            command += f" {self.target_ip}"

            # Run nmap and collect output
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if result.returncode == 0:
                output = result.stdout.decode("utf-8")
                self.output_signal.emit(output)
            else:
                self.error_signal.emit(result.stderr.decode("utf-8"))
        except subprocess.CalledProcessError as e:
            self.error_signal.emit(str(e))

class VulnerabilityCheckerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set the main window properties
        self.setWindowTitle('Advanced Scan')
        self.setGeometry(250, 100, 800, 600)

        # Create UI elements
        self.label = QLabel("Enter Target IP or IP Range:")
        self.target_ip_input = QLineEdit()
        self.scan_speed_label = QLabel("Scan Speed (-T1 to -T5):")
        self.scan_speed_input = QLineEdit()
        self.ports_label = QLabel("Ports to Scan (e.g., 80,443):")
        self.ports_input = QLineEdit()
        self.os_detection_checkbox = QCheckBox("Enable OS Detection")
        self.dark_mode_checkbox = QCheckBox("Enable Dark Mode")
        self.start_button = QPushButton("Start Vulnerability Scan")
        self.save_button = QPushButton("Save Report")
        self.export_json_button = QPushButton("Export as JSON")
        self.export_json_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.result_display = QTextEdit()
        self.result_display.setReadOnly(True)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.target_ip_input)
        layout.addWidget(self.scan_speed_label)
        layout.addWidget(self.scan_speed_input)
        layout.addWidget(self.ports_label)
        layout.addWidget(self.ports_input)
        layout.addWidget(self.os_detection_checkbox)
        layout.addWidget(self.dark_mode_checkbox)
        layout.addWidget(self.start_button)
        layout.addWidget(self.result_display)
        layout.addWidget(self.save_button)
        layout.addWidget(self.export_json_button)

        # Central widget
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Button connections
        self.start_button.clicked.connect(self.start_scan)
        self.save_button.clicked.connect(self.save_report)
        self.export_json_button.clicked.connect(self.export_to_json)
        self.dark_mode_checkbox.stateChanged.connect(self.toggle_dark_mode)

        # Vulners Scan thread instance
        self.scan_thread = None
        self.scan_result = ""

        # Check if Nmap is installed
        if not self.check_nmap_installed():
            self.prompt_nmap_installation()

    def check_nmap_installed(self):
        """Check if Nmap is installed on the system."""
        return shutil.which("nmap") is not None

    def prompt_nmap_installation(self):
        """Prompt the user to install Nmap."""
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setText("Nmap is not installed.")
        msg.setInformativeText("Nmap is required for vulnerability scanning. Please install it from the following link:")
        msg.setWindowTitle("Nmap Not Found")
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.setDetailedText("Download Nmap from: https://nmap.org/download.html")
        msg.buttonClicked.connect(self.open_nmap_download_page)
        msg.exec()

    def open_nmap_download_page(self, button):
        """Open the Nmap download page in the default web browser."""
        webbrowser.open("https://nmap.org/download.html")

    def start_scan(self):
        target_ip = self.target_ip_input.text()
        scan_speed = self.scan_speed_input.text()
        ports = self.ports_input.text()
        os_detection = self.os_detection_checkbox.isChecked()

        if not self.is_valid_ip_or_range(target_ip):
            QMessageBox.warning(self, "Input Error", "Please enter a valid target IP address or range.")
            return

        self.result_display.clear()
        self.start_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.export_json_button.setEnabled(False)
        self.target_ip_input.setEnabled(False)
        self.scan_speed_input.setEnabled(False)

        # Start the scan in a background thread
        self.scan_thread = VulnersScanThread(target_ip, scan_speed, ports, os_detection)
        self.scan_thread.output_signal.connect(self.display_scan_result)
        self.scan_thread.error_signal.connect(self.display_error_message)
        self.scan_thread.start()

    def display_scan_result(self, result):
        self.scan_result = result
        self.result_display.append(result)  # Display Nmap output in the GUI
        
        # Parse CVSS score from scan result (if available)
        self.extract_and_calculate_cvss(result)

        self.start_button.setEnabled(True)
        self.save_button.setEnabled(True)
        self.export_json_button.setEnabled(True)
        self.target_ip_input.setEnabled(True)
        self.scan_speed_input.setEnabled(True)

    def extract_and_calculate_cvss(self, result):
        """Extract CVSS v3 score from Nmap result and calculate the score components."""
        # Regex to find CVSS v3 score in the output (e.g., CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
        cvss_pattern = r"CVSS:(\d\.\d)/([A-Z]+):([A-Z]+)/([A-Z]+)/([A-Z]+)/([A-Z]+)/([A-Z]+)/([A-Z]+)"
        match = re.search(cvss_pattern, result)
        
        if match:
            # Extract the CVSS components from the regex match
            base_score = match.group(1)
            access_vector = match.group(2)
            access_complexity = match.group(3)
            privilege_required = match.group(4)
            user_interaction = match.group(5)
            scope = match.group(6)
            confidentiality_impact = match.group(7)
            integrity_impact = match.group(8)
            availability_impact = match.group(9)
            
            # Create a CVSS3 object
            cvss = CVSS3(
                base_score=base_score,
                access_vector=access_vector,
                access_complexity=access_complexity,
                privilege_required=privilege_required,
                user_interaction=user_interaction,
                scope=scope,
                confidentiality_impact=confidentiality_impact,
                integrity_impact=integrity_impact,
                availability_impact=availability_impact
            )

            # Display the CVSS score and the vector string
            self.result_display.append(f"\nCVSS v3 Score: {cvss.base_score}")
            self.result_display.append(f"CVSS v3 Vector: {cvss.vector_string}")
        else:
            self.result_display.append("\nNo CVSS v3 score found in the Nmap scan result.")

    def display_error_message(self, error_message):
        self.result_display.setPlainText(error_message)
        self.start_button.setEnabled(True)
        self.target_ip_input.setEnabled(True)
        self.scan_speed_input.setEnabled(True)

    def save_report(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Report", f"vulnerability_report_{stringtoday}.txt", "Text Files (*.txt)")
        if filename:
            with open(filename, "w") as file:
                file.write(self.result_display.toPlainText())

    def export_to_json(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Export Report", f"vulnerability_report_{stringtoday}.json", "JSON Files (*.json)")
        if filename:
            json_data = {"scan_results": self.scan_result}
            with open(filename, "w") as json_file:
                json.dump(json_data, json_file, indent=4)

    def is_valid_ip_or_range(self, ip):
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        range_pattern = r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
        return re.match(ip_pattern, ip) or re.match(range_pattern, ip)

    def toggle_dark_mode(self, state):
        if state == 2:
            self.setStyleSheet("background-color: black; color: white;")
        else:
            self.setStyleSheet("background-color: white; color: black;")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = VulnerabilityCheckerApp()
    window.show()
    sys.exit(app.exec())
