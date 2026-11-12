#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

APPLET_ID = "linspectacles-cpu-vulnerabilities"
APPLET_NAME = "CPU Vulnerabilities"
APPLET_VERSION = "0.0.5"
APPLET_AUTHOR = "brunonlinespace"
APPLET_EDITOR = "brunonlinespace"
APPLET_PUBLISHER = "brunonlinespace"
APPLET_ORGANIZATION_ID = "linspectacles"
APPLET_ORGANIZATION_URL = "https://github.com/linspectacles/"
APPLET_REPOSITORY = "https://github.com/linspectacles/cpu-vulnerabilities"

from pathlib import Path
from PyQt6.QtCore import QSettings, Qt, QUrl
from PyQt6.QtGui import QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout,
    QLabel, QMessageBox, QPushButton, QTableWidgetItem, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
)
from ._support import BaseInspectorTab, export_records_dialog, metadata_font_qss


def _classify_vulnerability_status(status):
    value = str(status or "").strip()
    lower = value.lower()
    if lower.startswith("not affected"):
        return "Not affected"
    if lower.startswith("mitigation:"):
        return "Mitigated"
    if lower.startswith("vulnerable"):
        return "Vulnerable"
    if lower.startswith("unknown"):
        return "Unknown"
    if not value:
        return "Empty status"
    return "Reported"


def _collect_cpu_vulnerabilities(root=Path("/sys/devices/system/cpu/vulnerabilities")):
    root = Path(root)
    if not root.exists():
        return {"available": False, "records": [], "error": "Vulnerability sysfs directory is not exposed."}
    try:
        entries = sorted((p for p in root.iterdir() if p.is_file()), key=lambda p: p.name.lower())
    except PermissionError:
        return {"available": False, "records": [], "error": "Access denied while reading CPU vulnerability state."}
    except OSError as exc:
        return {"available": False, "records": [], "error": f"Unable to read CPU vulnerability state: {exc}"}

    records = []
    for entry in entries:
        try:
            # Preserve sysfs text as read; normalization is classification-only.
            status = entry.read_text(encoding="utf-8", errors="replace")
            read_state = "Available"
            read_error = ""
        except PermissionError as exc:
            status = ""
            read_state = "Access denied"
            read_error = str(exc) or "Permission denied while reading the entry."
        except OSError as exc:
            status = ""
            read_state = "Read error"
            read_error = str(exc)
        records.append({
            "entry": entry.name,
            "classification": _classify_vulnerability_status(status) if read_state == "Available" else read_state,
            "status": status,
            "source_path": str(entry),
            "read_state": read_state,
            "read_error": read_error,
        })
    return {"available": True, "records": records, "error": ""}



class CpuVulnerabilitiesOptionsDialog(QDialog):
    """Kernel Modules-authoritative Options tab structure for CPU Vulnerabilities."""

    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Options — CPU Vulnerabilities")
        self.resize(980, 720)

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # Appearance: the Kernel Modules geometry and controls.
        appearance_page = QWidget()
        appearance_layout = QVBoxLayout(appearance_page)
        appearance_layout.setContentsMargins(12, 12, 12, 12)
        appearance_layout.setSpacing(10)
        appearance_heading = QLabel("Metadata display")
        heading_font = appearance_heading.font()
        heading_font.setBold(True)
        appearance_heading.setFont(heading_font)
        appearance_layout.addWidget(appearance_heading)
        appearance_note = QLabel(
            "Choose how the inventory and Metadata Details panes are arranged. "
            "This CPU Vulnerabilities setting is remembered."
        )
        appearance_note.setWordWrap(True)
        appearance_layout.addWidget(appearance_note)

        layout_row = QHBoxLayout()
        layout_row.addWidget(QLabel("Record details layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Horizontal", "Vertical"])
        self.layout_combo.setCurrentText(
            "Vertical" if owner.details_orientation == "vertical" else "Horizontal"
        )
        self.layout_combo.currentTextChanged.connect(self._layout_changed)
        layout_row.addWidget(self.layout_combo)
        layout_row.addStretch(1)
        appearance_layout.addLayout(layout_row)

        self.show_metadata_panel = QCheckBox("Show Metadata Details panel (F3)")
        self.show_metadata_panel.setChecked(owner.metadata_panel_visible)
        self.show_metadata_panel.toggled.connect(self._metadata_panel_changed)
        appearance_layout.addWidget(self.show_metadata_panel)
        shortcut_note = QLabel(
            "F3 hides/restores Metadata Details. Shift+F5 refreshes CPU vulnerability state. "
            "Ctrl+L toggles Horizontal/Vertical layout. Ctrl+/ opens Options. "
            "Ctrl+A selects all classifications; Ctrl+1–8 selects a specific classification."
        )
        shortcut_note.setWordWrap(True)
        appearance_layout.addWidget(shortcut_note)
        appearance_layout.addStretch(1)
        tabs.addTab(appearance_page, "Appearance")

        # Sources: exactly the Kernel Modules text-field treatment.
        sources_page = QWidget()
        sources_layout = QVBoxLayout(sources_page)
        sources_layout.setContentsMargins(12, 12, 12, 12)
        sources_layout.setSpacing(10)
        sources_heading = QLabel("Data Sources")
        sources_heading_font = sources_heading.font()
        sources_heading_font.setBold(True)
        sources_heading_font.setPointSize(max(sources_heading_font.pointSize(), 11))
        sources_heading.setFont(sources_heading_font)
        sources_layout.addWidget(sources_heading)
        sources_note = QLabel(
            "Linux interfaces used by this read-only CPU vulnerability inspector."
        )
        sources_note.setWordWrap(True)
        sources_layout.addWidget(sources_note)

        sources_text = QTextEdit()
        sources_text.setReadOnly(True)
        sources_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        chosen_font = getattr(owner, "_metadata_font", None)
        if chosen_font is not None:
            sources_text.setFont(chosen_font)
            sources_text.document().setDefaultFont(chosen_font)
            sources_text.setCurrentFont(chosen_font)
            font_rule = metadata_font_qss(chosen_font)
        else:
            font_rule = ""
        sources_text.setStyleSheet(
            "QTextEdit { "
            + font_rule
            + " background-color: #151719; color: #dcdcdc; "
              "border: 1px solid #333333; }"
        )
        source_key_format = QTextCharFormat()
        source_key_format.setForeground(QColor("#9cdcfe"))
        source_key_format.setFontWeight(600)
        source_value_format = QTextCharFormat()
        source_value_format.setForeground(QColor("#dcdcdc"))
        cursor = sources_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for line in owner.sources_text().splitlines():
            if line and not line[:1].isspace():
                cursor.insertText(line + "\n", source_key_format)
            else:
                cursor.insertText(line + "\n", source_value_format)
        sources_text.setTextCursor(cursor)
        sources_text.moveCursor(QTextCursor.MoveOperation.Start)
        sources_layout.addWidget(sources_text, 1)
        tabs.addTab(sources_page, "Sources")

        # Export: keep the Kernel Modules options tab and already-collected-data policy.
        export_page = QWidget()
        export_layout = QVBoxLayout(export_page)
        export_layout.setContentsMargins(12, 12, 12, 12)
        export_layout.setSpacing(10)
        export_heading = QLabel("Export details")
        export_heading_font = export_heading.font()
        export_heading_font.setBold(True)
        export_heading.setFont(export_heading_font)
        export_layout.addWidget(export_heading)
        export_note = QLabel("Select the CPU vulnerability details to include in the export. Only visible, already-collected records are exported.")
        export_note.setWordWrap(True)
        export_layout.addWidget(export_note)
        self.export_checks = []
        for key, label in (
            ("entry", "Entry"),
            ("classification", "Classification"),
            ("status", "Kernel Status"),
            ("source_path", "Source Path"),
            ("read_state", "Read State"),
            ("read_error", "Read Error"),
        ):
            checkbox = QCheckBox(label)
            checkbox.setChecked(True)
            self.export_checks.append((key, label, checkbox))
            export_layout.addWidget(checkbox)
        self.export_metadata = QCheckBox("Metadata Details")
        self.export_metadata.setChecked(False)
        export_layout.addWidget(self.export_metadata)
        export_layout.addStretch(1)
        export_row = QHBoxLayout()
        export_row.addStretch(1)
        export_button = QPushButton("Export...")
        export_button.clicked.connect(self._export_selected)
        export_row.addWidget(export_button)
        export_layout.addLayout(export_row)
        tabs.addTab(export_page, "Export")

        # About: the Kernel Modules title/icon/about presentation.
        about_page = QWidget()
        about_layout = QVBoxLayout(about_page)
        about_layout.setContentsMargins(24, 20, 24, 18)
        about_layout.setSpacing(8)
        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(112, 112)
        icon_path = Path(__file__).resolve().parent / "icon.png"
        if icon_path.is_file():
            pixmap = QPixmap(str(icon_path))
            if not pixmap.isNull():
                icon_label.setPixmap(pixmap.scaled(
                    112, 112, Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                ))
        about_layout.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignHCenter)
        name = QLabel("<h2 style='margin:0'>CPU Vulnerabilities</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(name)
        version = QLabel(f"Version {APPLET_VERSION}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(version)
        slogan = QLabel("<b>Expose. Explore. Explain.</b>")
        slogan.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(slogan)
        description = QLabel(
            "A read-only LinSpectacles applet that reports Linux kernel-provided CPU "
            "vulnerability and mitigation states. It does not infer an overall secure/unsafe verdict."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(description)
        details = QLabel(
            "<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> "
            f"<a href='{APPLET_ORGANIZATION_URL}'>{APPLET_ORGANIZATION_ID}</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details.setOpenExternalLinks(True)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(details)
        copyright_label = QLabel(
            "Copyright © 2026 "
            "<a href='https://github.com/brunonlinespace'>brunonlinespace</a>"
        )
        copyright_label.setOpenExternalLinks(True)
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(copyright_label)
        license_label = QLabel("Licensed under GNU GPLv3 or later.")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(license_label)
        readme_url = QUrl.fromLocalFile(str(Path(__file__).resolve().parent.parent / "README.md")).toString()
        license_url = QUrl.fromLocalFile(str(Path(__file__).resolve().parent.parent / "LICENSE")).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{license_url}'>License</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{APPLET_REPOSITORY}'>Repository</a>"
        )
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(links)
        about_layout.addStretch(1)
        tabs.addTab(about_page, "About")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _layout_changed(self, text):
        self.owner.set_details_orientation(str(text).strip().lower(), persist=True)

    def _metadata_panel_changed(self, visible):
        self.owner.set_metadata_panel_visible(bool(visible), persist=True)

    def _export_selected(self):
        chosen = [(key, label, 140, "left") for key, label, check in self.export_checks if check.isChecked()]
        if self.export_metadata.isChecked():
            chosen.append(("metadata_details", "Metadata Details", 520, "left"))
        if not chosen:
            QMessageBox.information(self, "Export", "Select at least one detail to export.")
            return
        records = self.owner.get_visible_records()
        if not records:
            QMessageBox.information(self, "Export", "There are no visible CPU vulnerability entries to export.")
            return
        selected_keys = [key for key, _label, _width, _alignment in chosen]
        exported = []
        for record in records:
            item = {key: record.get(key, "") for key in selected_keys if key != "metadata_details"}
            if self.export_metadata.isChecked():
                item["metadata_details"] = self.owner.metadata_details_for_export(record)
            exported.append(item)
        path = export_records_dialog(
            self, APPLET_NAME, exported, columns=chosen,
            sections={
                "Source": "/sys/devices/system/cpu/vulnerabilities/*",
                "Interpretation": "Kernel-reported state only; no overall security verdict is inferred.",
            },
        )
        if path is not None:
            self.owner.set_status(f"Exported visible vulnerability entries to {path}")



class CpuVulnerabilitiesTab(BaseInspectorTab):
    """Kernel Modules inventory/metadata shell with original Hardware Topology CPU vulnerability data."""

    NUMERIC_COLUMNS = set()
    CLASSIFICATIONS = (
        "All Classifications", "Vulnerable", "Mitigated", "Not affected",
        "Unknown", "Reported", "Empty status", "Access denied", "Read error",
    )

    def __init__(self, parent=None):
        columns = [
            ("entry", "Entry", 210, "left"),
            ("classification", "Classification", 140, "left"),
            ("status", "Kernel Status", 450, "left"),
        ]
        super().__init__("Total CPU Vulnerabilities", columns, self.CLASSIFICATIONS, parent)
        self.export_title = APPLET_NAME
        self._settings = QSettings("brunonlinespace", "CPU Vulnerabilities")
        self._snapshot = {"available": False, "records": [], "error": "Not collected."}
        self.search_entry.setPlaceholderText("Search vulnerability entries or kernel status...")
        self.category_label.setText("Classification:")
        self.export_btn.setText("Options...")
        try:
            self.export_btn.clicked.disconnect()
        except TypeError:
            pass
        self.export_btn.clicked.connect(self.show_options)
        self.export_btn.setEnabled(True)

        self.details_orientation = "horizontal"
        self._load_details_orientation()
        self.metadata_panel_visible = True
        self._load_metadata_panel_visibility()
        self._shortcuts = []
        self._install_shortcuts()
        self.load_modules()

    def load_modules(self):
        # This is the exact Hardware Topology collector; only the surrounding UI moves.
        try:
            self._snapshot = _collect_cpu_vulnerabilities()
        except Exception as exc:
            self._snapshot = {"available": False, "records": [], "error": str(exc)}
        self.modules_data = [dict(row, category=row["classification"]) for row in self._snapshot.get("records", [])]
        self.stats_label.setText(f"{self.total_label_text}: {len(self.modules_data)}")
        self.filter_modules()
        if not self._snapshot.get("available", False):
            self.set_status(self._snapshot.get("error") or "CPU vulnerability state is unavailable.")
        elif not self.modules_data:
            self.set_status("0 CPU vulnerability entries reported by the kernel.")
        else:
            self.set_status(f"{len(self.modules_data)} kernel-reported CPU vulnerability entries.")

    def filter_modules(self, *_):
        # Kernel Modules' inventory -> visible selection -> Metadata Details synchronization.
        # Only 'All Classifications' differs from its standard 'All Categories' selector.
        query = self.search_entry.text().strip().lower()
        selected = self.category_dropdown.currentText()
        matches = [
            item for item in self.modules_data
            if (selected == "All Classifications" or item.get("classification") == selected)
            and (not query or any(query in str(item.get(k, "")).lower()
                                  for k in ("entry", "classification", "status", "source_path", "read_state", "read_error")))
        ]
        blocked = self.table.blockSignals(True)
        try:
            self.clear_info()
            self.table.clearSelection()
            self.table.setCurrentCell(-1, -1)
            self.table.setSortingEnabled(False)
            self.table.setRowCount(len(matches))
            for row, record in enumerate(matches):
                for col, (key, _label, _width, _alignment) in enumerate(self.columns):
                    cell = QTableWidgetItem(str(record.get(key, "")))
                    if col == 0:
                        cell.setData(Qt.ItemDataRole.UserRole, record)
                    self.table.setItem(row, col, cell)
            if matches:
                self.table.setCurrentCell(0, 0)
                self.table.selectRow(0)
        finally:
            self.table.blockSignals(blocked)
        if matches:
            self.on_module_select()
        else:
            self.clear_info()
        if query or selected != "All Classifications":
            self.filter_status_lbl.setText(f"(Showing {len(matches)} of {len(self.modules_data)} items)")
        else:
            self.filter_status_lbl.clear()
        self.export_btn.setEnabled(True)

    def get_visible_records(self):
        visible = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item is not None:
                record = item.data(Qt.ItemDataRole.UserRole)
                if record is not None:
                    visible.append(record)
        return visible

    @staticmethod
    def metadata_details_for_export(record):
        lines = [
            "--- Vulnerability ---",
            f"Entry: {record.get('entry', 'Not reported')}",
            f"Classification: {record.get('classification', 'Not reported')}",
        ]
        status = str(record.get("status", ""))
        read_state = str(record.get("read_state", "Not reported"))
        if read_state != "Available":
            # Do not mislabel an applet-created acquisition error as kernel text.
            lines.append("Kernel Status: Unavailable (read failed)")
        elif not status.strip():
            lines.append("Kernel Status: Empty response")
        else:
            lines.append(f"Raw Kernel Status: {status}")
            normalized = status.strip()
            if normalized.lower().startswith("mitigation:"):
                lines.extend([
                    "", "--- Mitigation ---",
                    f"Reported Mitigation: {normalized[len('Mitigation:'):].strip() or 'Not reported'}",
                ])
        lines.extend([
            "", "--- Source ---",
            f"Source Path: {record.get('source_path', 'Not reported')}",
            "Provider: Linux CPU vulnerability sysfs",
            f"Read State: {read_state}",
        ])
        read_error = str(record.get("read_error", ""))
        if read_state != "Available" and read_error:
            lines.append(f"Read Error: {read_error}")
        lines.extend([
            "",
            "Interpretation note: classification reports kernel wording or acquisition state; no overall secure/unsafe verdict is derived.",
        ])
        return "\n".join(lines)

    def on_module_select(self):
        record = self.current_record()
        if not record:
            self.clear_info()
            return
        # Keep the authoritative Kernel Modules metadata rendering path so
        # host-applied metadata font settings remain effective.
        self.clear_info()
        self.append_info(self.metadata_details_for_export(record))
        self.info_text.moveCursor(QTextCursor.MoveOperation.Start)
        self.info_text.verticalScrollBar().setValue(0)
        self.set_status(f"Inspecting kernel-reported CPU vulnerability [{record.get('entry', '')}].")

    @staticmethod
    def sources_text():
        return (
            "CPU Vulnerabilities is read-only. It reports the running kernel's CPU vulnerability and mitigation state.\n\n"
            "Kernel-reported vulnerability entries and status text\n"
            "  /sys/devices/system/cpu/vulnerabilities/*\n\n"
            "Important distinctions\n"
            "  Each sysfs file is reported as one inventory entry; its text is preserved as the kernel reports it.\n"
            "  Classification is an aid to filtering the kernel's own text, not an independent vulnerability assessment.\n"
            "  No overall secure/unsafe verdict is inferred from reported mitigation or vulnerability states.\n"
            "  Empty responses and read errors are identified separately from kernel-reported statuses; no escalation is performed."
        )

    def show_options(self):
        dialog = CpuVulnerabilitiesOptionsDialog(self)
        dialog.exec()

    def _add_shortcut(self, sequence, callback):
        shortcut = QShortcut(QKeySequence(sequence), self)
        shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        shortcut.activated.connect(callback)
        self._shortcuts.append(shortcut)
        return shortcut

    def _install_shortcuts(self):
        self._add_shortcut("F3", self.toggle_metadata_panel)
        self._add_shortcut("Ctrl+L", self.toggle_details_orientation)
        self._add_shortcut("Shift+F5", self.load_modules)
        self._add_shortcut("Ctrl+/", self.show_options)
        self._add_shortcut("Ctrl+A", lambda: self._select_category(0))
        for index in range(1, len(self.CLASSIFICATIONS)):
            self._add_shortcut(f"Ctrl+{index}", lambda i=index: self._select_category(i))

    def _select_category(self, index):
        if 0 <= index < self.category_dropdown.count():
            self.category_dropdown.setCurrentIndex(index)

    def toggle_details_orientation(self):
        target = "vertical" if self.details_orientation == "horizontal" else "horizontal"
        self.set_details_orientation(target, persist=True)

    def _load_metadata_panel_visibility(self):
        value = self._settings.value("metadata_panel_visible", True)
        if isinstance(value, str):
            visible = value.strip().lower() not in {"0", "false", "no", "off"}
        else:
            visible = bool(value)
        self.set_metadata_panel_visible(visible, persist=False)

    def set_metadata_panel_visible(self, visible, *, persist=True):
        self.metadata_panel_visible = bool(visible)
        details_panel = self.splitter.widget(1)
        if details_panel is not None:
            details_panel.setVisible(self.metadata_panel_visible)
        if self.metadata_panel_visible:
            self.set_details_orientation(self.details_orientation, persist=False)
        if persist:
            self._settings.setValue("metadata_panel_visible", self.metadata_panel_visible)
            self._settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible, persist=True)

    def _load_details_orientation(self):
        orientation = str(self._settings.value("details_orientation", "horizontal") or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.set_details_orientation(orientation, persist=False)

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.details_orientation = orientation
        details_panel = self.splitter.widget(1)
        details_layout = details_panel.layout() if details_panel is not None else None
        if orientation == "vertical":
            self.splitter.setOrientation(Qt.Orientation.Vertical)
            if details_layout is not None:
                details_layout.setContentsMargins(0, 8, 0, 0)
            self.splitter.setSizes([430, 330])
        else:
            self.splitter.setOrientation(Qt.Orientation.Horizontal)
            if details_layout is not None:
                details_layout.setContentsMargins(8, 0, 0, 0)
            self.splitter.setSizes([480, 700])
        if persist:
            self._settings.setValue("details_orientation", orientation)
            self._settings.sync()


def create_applet(parent=None):
    return CpuVulnerabilitiesTab(parent=parent)


def run_standalone():
    import sys
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from ._support import STANDALONE_STYLESHEET
    app = QApplication(sys.argv)
    app.setApplicationName(APPLET_NAME)
    app.setOrganizationName(APPLET_ORGANIZATION_ID)
    icon_path = Path(__file__).resolve().parent / "icon.png"
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    app.setStyleSheet(STANDALONE_STYLESHEET)
    window = QMainWindow()
    if icon_path.is_file():
        window.setWindowIcon(QIcon(str(icon_path)))
    window.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet")
    window.resize(1200, 780)
    window.setCentralWidget(create_applet())
    window.show()
    return app.exec()
