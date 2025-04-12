import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QTextEdit, 
                            QFileDialog, QTabWidget, QTableWidget, QTableWidgetItem,
                            QMessageBox, QProgressBar, QGroupBox, QSplitter,
                            QScrollArea, QFrame, QComboBox, QLineEdit, QStyle)
import sqlite3
from PyQt6.QtCore import Qt, QThread,pyqtSignal, QSize,QTimer
from PyQt6.QtGui import QIcon, QFont, QPalette, QColor,QPixmap,QTextCursor
import json

from url_checker import scan_url_virustotal
from googleapiclient.discovery import build
from google_auth import authenticate_user
from googleapiclient.errors import HttpError
from email_analyzer import analyze_email_headers
from attachment_analysis import scan_attachment
from email_security_checks import run_security_checks
import base64, tempfile, time
from get_gmail_service import get_gmail_service
from legitimacy_checker import calculate_legitimacy_score

class GmailMonitorThread(QThread):
    update_signal = pyqtSignal(dict)  # Emits a dictionary with detailed email info
    error_signal = pyqtSignal(str)

    def __init__(self, service, parent=None):
        super().__init__(parent)
        self.service = service
        self.running = True
        self.processed_count = 0
        self.suspicious_count = 0
        self.malicious_count = 0

    def run(self):
        print("Monitoring thread started")  # Debug log
        last_checked_id = None

        while self.running:
            try:
                print("Checking for new messages...")  # Debug log
                results = self.service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=5).execute()
                messages = results.get('messages', [])
                print(f"Found {len(messages)} messages")  # Debug log

                for message in messages:
                    msg_id = message['id']
                    if msg_id == last_checked_id:
                        continue

                    print(f"Processing new message: {msg_id}")  # Debug log
                    msg = self.service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
                    raw_data = base64.urlsafe_b64decode(msg['raw'].encode('ASCII'))
                    email_path = os.path.join(tempfile.gettempdir(), f"{msg_id}.eml")
                    with open(email_path, 'wb') as f:
                        f.write(raw_data)

                    email_data = analyze_email_headers(email_path)
                    attachments = email_data.get('attachments', [])
                    attachment_results = [scan_attachment(f) for f in attachments]
                    security = run_security_checks(email_data.get("sender", ""), eml_path=email_path)

                    api_keys = self.get_api_keys()
                    vt_key = api_keys.get("virustotal_api_key", "")
                    score, verdict = calculate_legitimacy_score(security, attachment_results, email_data.get("urls", []), vt_key)

                    # Update counters
                    self.processed_count += 1
                    if verdict.lower() == "suspicious":
                        self.suspicious_count += 1
                    elif verdict.lower() == "malicious":
                        self.malicious_count += 1

                    # Emit detailed results
                    self.update_signal.emit({
                        "sender": email_data.get("sender", "Unknown"),
                        "subject": email_data.get("subject", "No subject"),
                        "date": email_data.get("date", "Unknown"),
                        "verdict": verdict,
                        "score": score,
                        "attachments": len(attachments),
                        "urls": len(email_data.get("urls", [])),
                        "security_checks": security,
                        "attachment_results": attachment_results
                    })

                    last_checked_id = msg_id
                time.sleep(30)

            except HttpError as e:
                self.error_signal.emit(f"Gmail API error: {str(e)}")
            except Exception as e:
                self.error_signal.emit(f"Error: {str(e)}")
                time.sleep(10)

    def stop(self):
        """Safely stop the monitoring thread"""
        print("Stopping monitor thread...")
        self.running = False
        self.quit()
        if not self.wait(5000):  # Wait up to 5 seconds
            print("Thread did not stop normally, forcing termination")
            self.terminate()

    def get_api_keys(self):
        try:
            with open("config.json", "r") as f:
                return json.load(f)
        except:
            return {}

class GmailAuthThread(QThread):
    success = pyqtSignal(object, str)  # Emits (service, email)
    error = pyqtSignal(str)

    def run(self):
        try:
            creds = authenticate_user()
            if creds:
                service = build('gmail', 'v1', credentials=creds)
                profile = service.users().getProfile(userId='me').execute()
                email = profile.get('emailAddress', 'Unknown')
                self.success.emit(service, email)
            else:
                self.error.emit("Authentication failed: No credentials returned.")
        except Exception as e:
            self.error.emit(str(e))

class EmailAnalysisThread(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            results = analyze_email_headers(self.file_path)
            self.finished.emit(results)
        except Exception as e:
            self.error.emit(str(e))


class ModernButton(QPushButton):
    def __init__(self, text, parent=None,primary=True):
        super().__init__(text, parent)
        color= "#2196F3" if primary else "#757575"
        hover_color="#1976D2" if primary else "#616161"
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                font-size: 14px;
                min-width: 120px
            }}
            QPushButton:hover {{
                background-color: {hover_color};
            }}
            QPushButton:pressed {{
                background-color: {hover_color};
                padding-left: 11px 19px 9px 21px;
               
            }}
            QPushButton:disabled {{
                background-color:#BDBDBD;
                color:#757575;
                }}

        """)


class ModernTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
                color: #212121;
            }
            QTextEdit:focus {
                border: 2px solid #2196F3;
            }
        """)


class ModernGroupBox(QGroupBox):
    def __init__(self, title, parent=None):
        super().__init__(title, parent)
        self.setStyleSheet("""
            QGroupBox {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 8px;
                margin-top: 16px;
                padding: 12px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 5px;
                color: #424242;
            }
        """)

class EmailAnalysisGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Email Security Analyzer")
        
        self.setGeometry(100, 100, 1400, 900)
        
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #F5F5F5;
            }
            QTabWidget::pane {
                border: none;
                background-color: #2196f3;
            }
            QTabBar::tab {
                background-color: #EEEEEE;
                color: #757575;
                padding: 12px 25px;
                border: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                margin-right: 2px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #2196F3;
                color: white;
            }
            QTabBar::tab:hover:!selected {
                background-color: #E0E0E0;
            }
            QStatusBar {
                background-color: #2196F3;
                color: white;
                padding: 5px;
                font-weight: bold;
            }
            QTableWidget {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                gridline-color: #F5F5F5;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background-color: #E3F2FD;
                color: #212121;
            }
            QHeaderView::section {
                background-color: #2196F3;
                color: white;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
            QComboBox {
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                padding: 8px;
                min-width: 150px;
                background-color: white;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: url(down_arrow.png);
                width: 12px;
                height: 12px;
            }
            QLineEdit {
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                padding: 10px;
                background-color: white;
            }
            QProgressBar {
                border: none;
                border-radius: 5px;
                background-color: #E0E0E0;
                height: 8px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
                border-radius: 5px;
            }
        """)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout=QVBoxLayout(main_widget)
        layout.setContentsMargins(20,20,20,20)
        layout.setSpacing(20)

        header=QWidget()
        header.setFixedHeight(80)
        header.setStyleSheet("""
            QWidget {
                background: qlinergradient(x1:0, y1:0, x2:1, y2:0, 
                                          stop:0 #1976D2, stop:1 #2196F3);
                border-radius: 10px;
            }
        """)

        header_layout=QHBoxLayout(header)
        header_layout.setContentsMargins(20,0,20,0)

        logo_label=QLabel()
        logo_pixmap = self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon).pixmap(32, 32)
        logo_label.setPixmap(logo_pixmap)
        header_layout.addWidget(logo_label)

        title =QLabel("Email Security Analyzer")
        title.setStyleSheet("""
                background-color: transparent;
                color: #800080;
                font-size: 24px;
                font-weight: bold;
                padding-left: 10px;
        """)

        header_layout.addWidget(title)
        header_layout.addStretch()

        layout.addWidget(header)

        tabs=QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background-color: #F5F5F5;
            }
        """)
        layout.addWidget(tabs)

        tabs.addTab(self.create_file_scan_tab(), self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon), "Email File Scan")
        tabs.addTab(self.create_gmail_tab(), self.style().standardIcon(QStyle.StandardPixmap.SP_DriveNetIcon), "Gmail Monitor")
        tabs.addTab(self.create_url_scan_tab(), self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView), "URL Scanning")
        tabs.addTab(self.create_settings_tab(), self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogInfoView), "Settings")

        self.load_settings()
        self.gmail_service = None
        self.gmail_thread = None

    def save_settings(self):
        config = {
            "virustotal_api_key": self.vt_api_key.text(),
            "google_api_key": self.google_api_key.text(),
            "market_api_key": self.mark_api_key.text()
        }
        with open("config.json", "w") as f:
            json.dump(config, f)
        QMessageBox.information(self, "Settings", "Settings saved successfully")
        self.statusBar().showMessage("Settings saved")

    def load_settings(self):
        try:
            with open("config.json", "r") as f:
                config = json.load(f)
            self.vt_api_key.setText(config.get("virustotal_api_key", ""))
            self.google_api_key.setText(config.get("google_api_key", ""))
            self.mark_api_key.setText(config.get("mark_api_key", ""))
        except FileNotFoundError:
            pass


    def create_file_scan_tab(self):
        tab=QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        file_group=ModernGroupBox("Email File Selection")
        file_layout=QVBoxLayout(file_group)

        file_select_layout=QHBoxLayout()
        self.file_path_label=QLabel("No file selected")
        self.file_path_label.setStyleSheet("""
            QLabel {
                color: #757575;
                font-size: 13px;
                padding: 10px;
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 5px;
            }
        """)

        file_button=ModernButton("Select Email File",primary=True)
        file_button.clicked.connect(self.select_file)
        file_select_layout.addWidget(self.file_path_label,stretch=2)
        file_select_layout.addWidget(file_button,stretch=1) 
        file_layout.addLayout(file_select_layout) 

        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        #Analysis group
        analysis_grp=ModernGroupBox("Analysis.......")
        analysis_layout=QVBoxLayout()
        analyze_button=ModernButton("Analyze",primary=True)
        
        #implement analyze function
        analyze_button.clicked.connect(self.analyze_email)
        analysis_layout.addWidget(analyze_button)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                border-radius: 4px;
                background-color: #E0E0E0;
                height: 8px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
                border-radius: 4px;
            }
        """)
        analysis_layout.addWidget(self.progress_bar)
        
        analysis_grp.setLayout(analysis_layout)
        layout.addWidget(analysis_grp)

        #Result group
        result_grp=ModernGroupBox("Analysis Results")
        result_layout=QVBoxLayout()

        # Create splitter for results
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #E0E0E0;
                height: 2px;
            }
        """)

        #Summary section
        summary_widget = QWidget()
        summary_layout = QVBoxLayout(summary_widget)
        summary_label = QLabel("Summary")
        summary_label.setStyleSheet("font-weight: bold; color: #424242;")
        summary_layout.addWidget(summary_label)
       

        #detail results section
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_label = QLabel("Detailed Analysis")
        details_label.setStyleSheet("font-weight: bold; color: #424242;")
        details_layout.addWidget(details_label)
        self.results_text = ModernTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMinimumHeight(300)
        details_layout.addWidget(self.results_text)
        splitter.addWidget(details_widget)

        result_layout.addWidget(splitter)
        result_grp.setLayout(result_layout)
        layout.addWidget(result_grp)


        return tab
    
    def create_gmail_tab(self):
        tab =QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        #Authentication group
        auth_frame=QFrame()
        auth_frame.setFrameStyle(QFrame.Shape.Panel | QFrame.Shadow.Raised)
        auth_layout=QHBoxLayout()

        self.auth_status=QLabel("Authenticated Status : Not Authenticated")
        self.auth_status.setStyleSheet("""
            QLabel {
                color: #757575;
                font-size: 13px;
                padding: 10px;
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                font-weight: bold;
            }
        """)
        auth_layout.addWidget(self.auth_status)

        self.auth_button=QPushButton("Authenticate Gmail")
        self.auth_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)

        self.auth_button.clicked.connect(self.authenticate_gmail)
        auth_layout.addWidget(self.auth_button)
        
        auth_frame.setLayout(auth_layout)
        layout.addWidget(auth_frame)

        # Status section
        status_frame = QFrame()
        status_frame.setFrameStyle(QFrame.Shape.Panel | QFrame.Shadow.Raised)
        status_layout = QHBoxLayout()
        
        self.monitoring_status = QLabel("Monitoring Status: Inactive")
        self.monitoring_status.setStyleSheet("color: #757575; font-weight: bold;")
        status_layout.addWidget(self.monitoring_status)
        
        self.start_monitoring_btn = QPushButton("Start Monitoring")
        self.start_monitoring_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
                color: #757575;
            }
        """)

        self.start_monitoring_btn.clicked.connect(self.toggle_monitoring)
        self.start_monitoring_btn.setEnabled(False)  # Initially disabled
        status_layout.addWidget(self.start_monitoring_btn)

        status_frame.setLayout(status_layout)
        layout.addWidget(status_frame)

        # Statistics section
        stats_frame = QFrame()
        stats_frame.setFrameStyle(QFrame.Shape.Panel | QFrame.Shadow.Raised)
        stats_layout = QHBoxLayout()
        
        self.emails_processed = QLabel("Emails Processed: 0")
        self.emails_processed.setStyleSheet("color: #1976D2; font-weight: bold; margin-right: 15px;")
        stats_layout.addWidget(self.emails_processed)
        
        self.suspicious_emails = QLabel("Suspicious Emails: 0")
        self.suspicious_emails.setStyleSheet("color: #F57C00; font-weight: bold; margin-right: 15px;")
        stats_layout.addWidget(self.suspicious_emails)
        
        self.malicious_emails = QLabel("Malicious Emails: 0")
        self.malicious_emails.setStyleSheet("color: #D32F2F; font-weight: bold;")
        stats_layout.addWidget(self.malicious_emails)
        
        stats_frame.setLayout(stats_layout)
        layout.addWidget(stats_frame)

       # Email log section
        log_frame = QFrame()
        log_frame.setFrameStyle(QFrame.Shape.Panel | QFrame.Shadow.Raised)
        log_layout = QVBoxLayout()
        
        log_label = QLabel("Email Monitoring Results")
        log_label.setStyleSheet("font-weight: bold; font-size: 14px;color:black; margin-bottom: 5px;")
        log_layout.addWidget(log_label)
        
        self.email_log = QTextEdit()
        self.email_log.setReadOnly(True)
        self.email_log.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 3px;
                padding: 10px;
            }
        """)
        self.email_log.setHtml('<div style="color: #757575; text-align: center; margin-top: 20px;">Please authenticate with Gmail to start monitoring...</div>')
        log_layout.addWidget(self.email_log)
        
        log_frame.setLayout(log_layout)
        layout.addWidget(log_frame)
        
        # Initialize Gmail service and monitoring thread
        self.gmail_service = None
        self.monitor_thread = None
        
        tab.setLayout(layout)

        return tab

    def create_url_scan_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        # URL Input Group
        url_group = ModernGroupBox("URL Scanning")
        url_layout = QVBoxLayout()
        url_layout.setSpacing(10)

        url_label = QLabel("Enter URL to Scan:")
        url_label.setStyleSheet("font-weight: bold; color: #424242;")
        url_layout.addWidget(url_label)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.setStyleSheet("""
            QLineEdit {
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                padding: 10px;
                color:black;
                background-color: white;
            }
        """)
        url_layout.addWidget(self.url_input)

        scan_button = ModernButton("Scan URL", primary=True)
        scan_button.clicked.connect(self.scan_url)
        url_layout.addWidget(scan_button)

        url_group.setLayout(url_layout)
        layout.addWidget(url_group)

        # Results Group
        results_group = ModernGroupBox("Scan Results")
        results_layout = QVBoxLayout()

        self.url_results = ModernTextEdit()
        self.url_results.setReadOnly(True)
        self.url_results.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 1px solid #E0E0E0;
                color: black;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        results_layout.addWidget(self.url_results)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        return tab

    def scan_url(self):
        url = self.url_input.text()
        if not url:
            QMessageBox.warning(self, "Error", "Please enter a URL to scan.")
            return

        self.statusBar().showMessage("Scanning URL via VirusTotal...")

        # Load API key from config
        try:
            with open("config.json", "r") as f:
                config = json.load(f)
            vt_api_key = config.get("virustotal_api_key")
        except:
            vt_api_key = None

        if not vt_api_key:
            QMessageBox.warning(self, "API Key Missing", "Please enter your VirusTotal API key in Settings.")
            return

        result = scan_url_virustotal(vt_api_key, url)
        if result["status"] == "success":
            stats = result["details"]
            msg = (
                f"📡 URL: {url}\n"
                f"✅ Scanned by {result['total_engines']} engines\n"
                f"Results:\n"
                f"- Harmless: {stats.get('harmless', 0)}\n"
                f"- Suspicious: {stats.get('suspicious', 0)}\n"
                f"- Malicious: {stats.get('malicious', 0)}\n"
                f"- Undetected: {stats.get('undetected', 0)}\n"
            )
        else:
            msg = f"❌ Scan failed: {result['details']}"

        self.url_results.setText(msg)
        self.statusBar().showMessage("URL scan completed.")


    def analyze_email(self):
        file_path = self.file_path_label.text()
        if file_path == "No file selected":
            QMessageBox.warning(self, "Error", "Please select an email file first")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(10)
        self.statusBar().showMessage("Analyzing email...")

        self.analysis_thread = EmailAnalysisThread(file_path)
        self.analysis_thread.finished.connect(self.on_analysis_finished)
        self.analysis_thread.error.connect(self.on_analysis_error)
        self.analysis_thread.start()

    def toggle_monitoring(self):
        try:
            if not hasattr(self, 'monitor_thread') or self.monitor_thread is None:
                # Starting monitoring
                if not self.gmail_service:
                    QMessageBox.warning(self, "Error", "Gmail service not initialized. Please authenticate first.")
                    return

                self.monitor_thread = GmailMonitorThread(self.gmail_service)
                self.monitor_thread.update_signal.connect(self.update_monitoring_results)
                self.monitor_thread.error_signal.connect(self.handle_monitoring_error)
                self.monitor_thread.start()

                # Update UI
                self.monitoring_status.setText("Monitoring Status: Active")
                self.monitoring_status.setStyleSheet("color: #4CAF50; font-weight: bold;")
                self.start_monitoring_btn.setText("Stop Monitoring")
            else:
                # Stopping monitoring
                self.monitor_thread.stop()
                self.monitor_thread = None
                self.monitoring_status.setText("Monitoring Status: Inactive")
                self.monitoring_status.setStyleSheet("color: #757575; font-weight: bold;")
                self.start_monitoring_btn.setText("Start Monitoring")
        except Exception as e:
            print(f"Error in toggle_monitoring: {str(e)}")
    
    def update_monitoring_results(self, result):
        try:
            # Update statistics
            self.emails_processed.setText(f"Emails Processed: {self.monitor_thread.processed_count}")
            self.suspicious_emails.setText(f"Suspicious Emails: {self.monitor_thread.suspicious_count}")
            self.malicious_emails.setText(f"Malicious Emails: {self.monitor_thread.malicious_count}")

            # Format the result for display
            verdict_color = {
                "safe": "#4CAF50",
                "suspicious": "#FF9800",
                "malicious": "#F44336"
            }.get(result["verdict"].lower(), "#757575")

            # Extract SPF, DKIM, and DMARC results
            security_checks = result.get("security_checks", {})
            spf_result = security_checks.get("spf", {}).get("spf", "N/A")
            dkim_result = security_checks.get("dkim", {}).get("dkim", "N/A")
            dmarc_result = security_checks.get("dmarc", {}).get("dmarc", "N/A")

            detailed_result = f"""
            <div style="background-color: #F5F5F5; border-left: 4px solid {verdict_color}; 
                        margin: 10px 0; padding: 10px; border-radius: 4px;">
                <div style="font-size: 14px; color: #212121;">
                    <b>Sender:</b> {result['sender']}<br>
                    <b>Subject:</b> {result['subject']}<br>
                    <b>Date:</b> {result['date']}<br>
                    <b>Verdict:</b> <span style="color: {verdict_color};">{result['verdict']}</span><br>
                    <b>Score:</b> {result['score']}<br>
                    <b>Attachments:</b> {result['attachments']}<br>
                    <b>URLs Found:</b> {result['urls']}<br>
                    <b>SPF:</b> {spf_result}<br>
                    <b>DKIM:</b> {dkim_result}<br>
                    <b>DMARC:</b> {dmarc_result}<br>
                </div>
            </div>
            <hr style="border: none; border-top: 1px solid #E0E0E0; margin: 15px 0;">
            """

            # Add new result at the top of the log
            cursor = self.email_log.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.insertHtml(detailed_result)

            # Ensure the new content is visible
            self.email_log.verticalScrollBar().setValue(0)

        except Exception as e:
            print(f"Error updating monitoring results: {str(e)}")
    
    def handle_monitoring_error(self, error_message):
        """Handle errors from the monitoring thread"""
        print(f"Monitoring error received: {error_message}")  # Debug log
        
        # Check if the error is critical
        critical_errors = [
            "Gmail service not initialized",
            "Failed to authenticate",
            "Invalid credentials",
            "Access denied"
        ]
        
        is_critical = any(error in error_message for error in critical_errors)
        
        if is_critical:
            # For critical errors, stop monitoring and show error dialog
            if hasattr(self, 'monitor_thread') and self.monitor_thread is not None:
                print("Stopping monitoring due to critical error")  # Debug log
                self.toggle_monitoring()  # Stop monitoring
            
            QMessageBox.critical(self, "Critical Error", 
                               f"Monitoring stopped due to critical error:\n\n{error_message}\n\n"
                               "Please check your authentication and try again.")
            
            # Reset authentication state
            self.auth_status.setText("Authentication Status: Not Authenticated")
            self.auth_status.setStyleSheet("color: #757575; font-weight: bold;")
            self.auth_button.setEnabled(True)
            self.start_monitoring_btn.setEnabled(False)
        else:
            # For non-critical errors, just show a warning
            QMessageBox.warning(self, "Monitoring Warning", error_message)
    
    def refresh_reports(self):
        try:
            conn = sqlite3.connect("phishing_reports.db")
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, score, verdict, details FROM reports")
            rows = cursor.fetchall()
            conn.close()
            
            self.reports_table.setRowCount(len(rows))
            for i, row in enumerate(rows):
                for j, value in enumerate(row[:4]):  # Only show first 4 columns
                    self.reports_table.setItem(i, j, QTableWidgetItem(str(value)))
                # Add date from details
                details = json.loads(row[4])
                date = details.get('headers', {}).get('Date', 'N/A')
                self.reports_table.setItem(i, 4, QTableWidgetItem(date))
            
            self.statusBar().showMessage(f"Reports refreshed: {len(rows)} entries")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error refreshing reports: {str(e)}")
            self.statusBar().showMessage("Failed to refresh reports")
    
    def filter_reports(self, filter_text):
        for row in range(self.reports_table.rowCount()):
            verdict = self.reports_table.item(row, 3).text()
            if filter_text == "All" or verdict == filter_text:
                self.reports_table.setRowHidden(row, False)
            else:
                self.reports_table.setRowHidden(row, True)
    
    def save_settings(self):
        # Save API keys to environment variables or config file
        # This is a placeholder - implement actual settings storage
        config = {
        "virustotal_api_key": self.vt_api_key.text(),
        "google_api_key": self.google_api_key.text(),
        "market_api_key": self.mark_api_key.text(),
        "whois_api_key": self.whois_api_key.text()
        }

        QMessageBox.information(self, "Settings", "Settings saved successfully")
        self.statusBar().showMessage("Settings saved")

    def on_analysis_finished(self, results):
        try:
            self.progress_bar.setValue(80)

            # Analyze attachments
            attachments = results.get("attachments", [])
            attachment_results = [scan_attachment(path) for path in attachments]
            results["attachment_analysis"] = attachment_results

            # Run security checks (SPF, DKIM, DMARC, WHOIS)
            sender = results.get("sender", "")
            file_path = self.file_path_label.text()
            security_checks = run_security_checks(sender, eml_path=file_path)

            results["email_security"] = security_checks

            # Build summary
            summary = (
                f"Sender: {results['sender']}\n"
                f"Subject: {results['subject']}\n"
                f"Date: {results['date']}\n"
                f"SPF: {security_checks.get('spf', {}).get('spf', 'N/A')}\n"
                f"DKIM: {security_checks.get('dkim', {}).get('dkim', 'N/A')}\n"
                f"DMARC: {security_checks.get('dmarc', {}).get('dmarc', 'N/A')}\n"
                f"URLs Found: {len(results.get('urls', []))}\n"
                f"Attachments: {len(attachments)}\n"
                
            )
            # self.summary_text.setText(summary)

            # Full detailed dump
            def format_detailed_report(results):
                lines = []

                # Email Summary
                lines.append("📬 EMAIL SUMMARY\n" + "-" * 18)
                lines.append(f"Sender:       {results['sender']}")
                lines.append(f"Subject:      {results['subject']}")
                lines.append(f"Date:         {results['date']}\n")

                # URL Section
                lines.append("🌐 URL ANALYSIS\n" + "-" * 18)
                urls = results.get("urls", [])
                if not urls:
                    lines.append("No URLs found.\n")
                for idx, url_obj in enumerate(urls, 1):
                    lines.append(f"[{idx}] {url_obj['url']}")
                    gsb = url_obj.get("google_safe_browsing", {}).get("status", "unknown")
                    vt = url_obj.get("virustotal", {}).get("status", "unknown")
                    whois = url_obj.get("whois", {}).get("status", "unknown")
                    lines.append(f"   - Google Safe Browsing: {'✅ Safe' if gsb == 'safe' else '⚠️ ' + gsb.capitalize()}")
                    lines.append(f"   - VirusTotal: {'✅ Safe' if vt == 'safe' else '❌ ' + vt.capitalize()}")
                    lines.append(f"   - WHOIS: {whois}\n")

                # Attachments
                lines.append("📎 ATTACHMENTS\n" + "-" * 18)
                if not results.get("attachments"):
                    lines.append("No attachments found.\n")
                else:
                    for att in results.get("attachment_analysis", []):
                        verdict = "✅ Clean"
                        if att.get("suspicious"):
                            verdict = f"❌ Suspicious - {att.get('reason')}"
                        lines.append(f"{att['file']}: {verdict}")
                        vt = att.get("virustotal", {}).get("details", {})
                        if isinstance(vt, dict):
                            lines.append(f"  - VT Malicious: {vt.get('malicious', 0)} | Suspicious: {vt.get('suspicious', 0)}\n")

                # Email Security
                sec = results.get("email_security", {})
                lines.append("🛡 EMAIL SECURITY\n" + "-" * 18)
                lines.append(f"SPF:   {'✅ Valid' if sec.get('spf', {}).get('spf') == 'valid' else '❌ Invalid'} → {sec.get('spf', {}).get('details')}")
                lines.append(f"DKIM:  {'✅ Valid' if sec.get('dkim', {}).get('dkim') == 'valid' else '⚠️ ' + sec.get('dkim', {}).get('dkim', '')} → {sec.get('dkim', {}).get('details')}")
                lines.append(f"DMARC: {'✅ Valid' if sec.get('dmarc', {}).get('dmarc') == 'valid' else '❌ Invalid'} → {sec.get('dmarc', {}).get('details')}")

                whois = sec.get("whois", {}).get("details", {})
                if isinstance(whois, dict):
                    lines.append("\nWHOIS:")
                    lines.append(f"   - Domain: {'✅ Registered' if whois.get('domain_registered') == 'yes' else '❌ Not Registered'}")
                    lines.append(f"   - Registrar: {whois.get('domain_registrar', {}).get('registrar_name', 'Unknown')}")
                    lines.append(f"   - Created: {whois.get('create_date')} | Expires: {whois.get('expiry_date')}")
                    lines.append(f"   - Organization: {whois.get('registrant_contact', {}).get('company', 'N/A')}")
                    lines.append(f"   - Country: {whois.get('registrant_contact', {}).get('country_name', 'N/A')}")

                # Final Verdict (optional logic can be added)
                lines.append("\n⚠️ FINAL VERDICT\n" + "-" * 18)
                if sec.get("dkim", {}).get("dkim") != "valid":
                    lines.append("This email appears suspicious:\n- Missing DKIM signature\n- Public domain used (gmail.com)\n- URL not found in VirusTotal")
                    lines.append("\n📌 Recommendation:\nDo not click any links. Verify the sender manually.")
                else:
                    lines.append("This email appears legitimate based on SPF, DKIM, and DMARC.")

                return "\n".join(lines)

            self.results_text.setText(format_detailed_report(results))


            self.statusBar().showMessage("Email and security checks complete")

        except Exception as e:
            self.statusBar().showMessage(f"Error displaying results: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)
            self.progress_bar.setValue(100)


   
    def on_analysis_error(self, error_msg):
        QMessageBox.critical(self, "Analysis Error", f"Failed to analyze email:\n{error_msg}")
        self.statusBar().showMessage("Analysis failed")
        self.progress_bar.setVisible(False)

    
    def authenticate_gmail(self):
        try:
            print("Starting Gmail authentication...")  # Debug log

            # Check if credentials.json exists
            credentials_path = os.path.join(os.path.dirname(__file__), "credentials.json")
            if not os.path.exists(credentials_path):
                QMessageBox.critical(self, "Error", "credentials.json not found. Please add your Google API credentials.")
                return

            # Authenticate user and get Gmail service
            self.gmail_service = get_gmail_service()

            if self.gmail_service:
                # Test the service with a simple API call
                try:
                    profile = self.gmail_service.users().getProfile(userId="me").execute()
                    email = profile.get("emailAddress", "Unknown")

                    # Update UI for successful authentication
                    self.auth_status.setText(f"Authenticated as: {email}")
                    self.auth_status.setStyleSheet("color: #4CAF50; font-weight: bold;")
                    self.auth_button.setEnabled(False)
                    self.start_monitoring_btn.setEnabled(True)
                    self.email_log.setHtml('<div style="color: #757575; text-align: center; margin-top: 20px;">Ready to start monitoring...</div>')
                    print("Gmail authentication successful")  # Debug log
                except Exception as test_error:
                    print(f"Service test failed: {str(test_error)}")  # Debug log
                    QMessageBox.critical(self, "Authentication Error", f"Failed to verify Gmail service: {str(test_error)}")
                    self.gmail_service = None
            else:
                QMessageBox.warning(self, "Authentication Required", "Failed to authenticate. Please try again.")
                print("Gmail authentication failed")  # Debug log
        except Exception as e:
            error_msg = f"Authentication error: {str(e)}"
            print(error_msg)  # Debug log
            QMessageBox.critical(self, "Authentication Error", error_msg)

            # Reset authentication state
            self.auth_status.setText("Authentication Status: Not Authenticated")
            self.auth_status.setStyleSheet("color: #757575; font-weight: bold;")
            self.auth_button.setEnabled(True)
            self.start_monitoring_btn.setEnabled(False)
            self.gmail_service = None

    def on_auth_success(self, service, email):
        self.gmail_service = service
        self.auth_status.setText(f"Authenticated as: {email}")
        self.auth_status.setStyleSheet("color: #4CAF50; font-weight: bold;")
        self.auth_button.setEnabled(False)
        self.start_monitoring_btn.setEnabled(True)
        self.email_log.setHtml('<div style="color: #757575; text-align: center; margin-top: 20px;">Ready to start monitoring...</div>')

    def on_auth_error(self, message):
        QMessageBox.critical(self, "Authentication Error", f"Gmail authentication failed:\n{message}")
        self.auth_status.setText("Authentication Status: Not Authenticated")
        self.auth_status.setStyleSheet("color: #D32F2F; font-weight: bold;")
        self.auth_button.setEnabled(True)
        self.start_monitoring_btn.setEnabled(False)




    def create_reports_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        # Controls group
        controls_group = ModernGroupBox("Report Controls")
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(10)
        
        refresh_button = ModernButton("Refresh Reports", primary=True)
        refresh_button.clicked.connect(self.refresh_reports)
        controls_layout.addWidget(refresh_button)

        # Filter controls
        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet("""
            QLabel {
                color: #424242;
                font-weight: bold;
            }
        """)
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "Suspicious", "Malicious", "Safe"])
        self.filter_combo.setStyleSheet("""
            QComboBox {
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                padding: 8px;
                color: #424242;
                min-width: 150px;
                background-color: white;
            }
            QComboBox::drop-down {
                border: none;
                width: 24px;
            }
            QComboBox::down-arrow {
                image: url(down_arrow.png);
                width: 12px;
                height: 12px;
            }
            QComboBox QAbstractItemView {
                border: 1px solid #E0E0E0;
                selection-background-color: #E3F2FD;
                selection-color: #212121;
            }
        """)
        #self.filter_combo.currentTextChanged.connect(self.filter_reports)
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_combo)
        controls_layout.addLayout(filter_layout)
        controls_layout.addStretch()
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)

        # Reports table
        table_group = ModernGroupBox("Security Reports")
        table_layout = QVBoxLayout()
        
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(5)
        self.reports_table.setHorizontalHeaderLabels(["ID", "Email", "Score", "Verdict", "Date"])
        self.reports_table.setStyleSheet("""
            QTableWidget {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                gridline-color: #F5F5F5;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #F5F5F5;
            }
            QTableWidget::item:selected {
                background-color: #E3F2FD;
                color: #212121;
            }
            QHeaderView::section {
                background-color: #2196F3;
                color: white;
                padding: 12px;
                border: none;
                font-weight: bold;
            }
            QScrollBar:vertical {
                border: none;
                background: #F5F5F5;
                width: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background: #BDBDBD;
                border-radius: 5px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
        """)

        self.reports_table.horizontalHeader().setStretchLastSection(True)
        self.reports_table.verticalHeader().setVisible(False)
        self.reports_table.setAlternatingRowColors(True)
        table_layout.addWidget(self.reports_table)
        
        table_group.setLayout(table_layout)
        layout.addWidget(table_group)


        return tab

    def create_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)

        # API Settings group
        api_group = ModernGroupBox("API Settings")
        api_layout = QVBoxLayout()
        api_layout.setSpacing(20)

         # VirusTotal API
        vt_layout = QVBoxLayout()
        vt_label = QLabel("VirusTotal API Key")
        vt_label.setStyleSheet("""
            QLabel {
                color: #424242;
                font-weight: bold;
                margin-bottom: 5px;
            }
        """)

        self.vt_api_key = QLineEdit()
        self.vt_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.vt_api_key.setStyleSheet("""
            QLineEdit {
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                padding: 10px;
                color: #424242;
                background-color: white;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QLineEdit:focus {
                border: 2px solid #2196F3;
            }
        """)
        vt_layout.addWidget(vt_label)
        vt_layout.addWidget(self.vt_api_key)
        api_layout.addLayout(vt_layout)

        # Google API
        google_layout = QVBoxLayout()
        google_label = QLabel("Google API Key")
        google_label.setStyleSheet("""
            QLabel {
                color: #424242;
                font-weight: bold;
                margin-bottom: 5px;
            }
        """)
        self.google_api_key = QLineEdit()
        self.google_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.google_api_key.setStyleSheet("""
            QLineEdit {
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                padding: 10px;
                color:black;
                background-color: white;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QLineEdit:focus {
                border: 2px solid #2196F3;
            }
        """)

        google_layout.addWidget(google_label)
        google_layout.addWidget(self.google_api_key)
        api_layout.addLayout(google_layout)
        
        

        # API MARKET
        mark_layout = QVBoxLayout()
        mark_label = QLabel("DNS API Key")
        mark_label.setStyleSheet("""
            QLabel {
                color: #424242;
                font-weight: bold;
                margin-bottom: 5px;
            }
        """)

        self.mark_api_key = QLineEdit()
        self.mark_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.mark_api_key.setStyleSheet("""
            QLineEdit {
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                color: #424242;
                padding: 10px;
                background-color: white;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QLineEdit:focus {
                border: 2px solid #2196F3;
            }
        """)
        mark_layout.addWidget(mark_label)
        mark_layout.addWidget(self.mark_api_key)
        api_layout.addLayout(mark_layout)

        # API MARKET
        whois_layout = QVBoxLayout()
        whois_label = QLabel("Whois API Key")
        whois_label.setStyleSheet("""
            QLabel {
                color: #424242;
                font-weight: bold;
                margin-bottom: 5px;
            }
        """)

        self.whois_api_key = QLineEdit()
        self.whois_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.whois_api_key.setStyleSheet("""
            QLineEdit {
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                color: #424242;
                padding: 10px;
                background-color: white;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QLineEdit:focus {
                border: 2px solid #2196F3;
            }
        """)
        whois_layout.addWidget(whois_label)
        whois_layout.addWidget(self.whois_api_key)
        api_layout.addLayout(whois_layout)

        save_button = ModernButton("Save Settings", primary=True)
        save_button.clicked.connect(self.save_settings)
        api_layout.addWidget(save_button)
        
        api_group.setLayout(api_layout)
        layout.addWidget(api_group)

        
        return tab
    

    def select_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Email File", "", "Email Files (*.eml);;All Files (*)")
        if file_name:
            self.file_path_label.setText(file_name)
            self.statusBar().showMessage(f"Selected file: {file_name}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window=EmailAnalysisGUI()
    window.show()
    sys.exit(app.exec())



