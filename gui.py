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
        tabs.addTab(QWidget(), self.style().standardIcon(QStyle.StandardPixmap.SP_DriveNetIcon), "Gmail Monitor")
        tabs.addTab(QWidget(), self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView), "Reports")
        tabs.addTab(QWidget(), self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogInfoView), "Settings")
        
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

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EmailAnalysisGUI()
    window.show()
    sys.exit(app.exec()) 