import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QTextEdit, 
                            QFileDialog, QTabWidget, QTableWidget, QTableWidgetItem,
                            QMessageBox, QProgressBar, QGroupBox, QSplitter,
                            QScrollArea, QFrame, QComboBox, QLineEdit, QStyle)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QPixmap

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
                background-color: #F5F5F5;
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
        """)
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Create header with gradient background
        header = QWidget()
        header.setFixedHeight(80)
        header.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                          stop:0 #1976D2, stop:1 #2196F3);
                border-radius: 10px;
            }
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 0, 20, 0)
        
        # Add logo/icon
        logo_label = QLabel()
        logo_pixmap = self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon).pixmap(32, 32)
        logo_label.setPixmap(logo_pixmap)
        header_layout.addWidget(logo_label)
        
        # Add title
        title = QLabel("Email Security Analyzer")
        title.setStyleSheet("""
            color: white;
            font-size: 24px;
            font-weight: bold;
            padding-left: 10px;
        """)
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        layout.addWidget(header)
        
        # Create tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Add File Scan tab
        file_scan_tab = QWidget()
        file_scan_layout = QVBoxLayout(file_scan_tab)
        
        # File selection group
        file_group = ModernGroupBox("Email File Selection")
        file_layout = QVBoxLayout()
        
        file_select_layout = QHBoxLayout()
        self.file_path_label = QLabel("No file selected")
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
        select_button = QPushButton("Select Email File")
        select_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        file_select_layout.addWidget(self.file_path_label, stretch=2)
        file_select_layout.addWidget(select_button, stretch=1)
        file_layout.addLayout(file_select_layout)
        
        file_group.setLayout(file_layout)
        file_scan_layout.addWidget(file_group)
        
        # Analysis group
        analysis_group = ModernGroupBox("Analysis")
        analysis_layout = QVBoxLayout()
        
        analyze_button = QPushButton("Analyze Email")
        analyze_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
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
        
        analysis_group.setLayout(analysis_layout)
        file_scan_layout.addWidget(analysis_group)
        
        # Results group
        results_group = ModernGroupBox("Analysis Results")
        results_layout = QVBoxLayout()
        
        # Summary section
        summary_label = QLabel("Summary")
        summary_label.setStyleSheet("font-weight: bold; color: #424242;")
        results_layout.addWidget(summary_label)
        
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                padding: 8px;
            }
        """)
        self.summary_text.setMaximumHeight(150)
        results_layout.addWidget(self.summary_text)
        
        # Detailed Analysis section
        detailed_label = QLabel("Detailed Analysis")
        detailed_label.setStyleSheet("font-weight: bold; color: #424242;")
        results_layout.addWidget(detailed_label)
        
        self.detailed_text = QTextEdit()
        self.detailed_text.setReadOnly(True)
        self.detailed_text.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 5px;
                padding: 8px;
            }
        """)
        results_layout.addWidget(self.detailed_text)
        
        results_group.setLayout(results_layout)
        file_scan_layout.addWidget(results_group)
        
        # Add tabs
        tabs.addTab(file_scan_tab, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon), "File Scan")
        tabs.addTab(self.create_gmail_tab(), self.style().standardIcon(QStyle.StandardPixmap.SP_DriveNetIcon), "Gmail Monitor")
        tabs.addTab(self.create_reports_tab(), self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView), "Reports")
        tabs.addTab(self.create_settings_tab(), self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogInfoView), "Settings")
        
        # Set status bar
        self.statusBar().setStyleSheet("""
            QStatusBar {
                background-color: #2196F3;
                color: white;
                font-weight: bold;
                padding: 5px;
            }
        """)
        self.statusBar().showMessage("Ready")

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

        # self.auth_button.clicked.connect(self.authenticate_gmail)
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

        # self.start_monitoring_btn.clicked.connect(self.start_monitoring)
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
        #refresh_button.clicked.connect(self.refresh_reports)
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
                color: #424242;
                padding: 8px;
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
        mark_label = QLabel("Disposable and DNS API Key")
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
        #save_button.clicked.connect(self.save_settings)
        api_layout.addWidget(save_button)
        
        api_group.setLayout(api_layout)
        layout.addWidget(api_group)

        
        return tab
    



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EmailAnalysisGUI()
    window.show()
    sys.exit(app.exec()) 