"""Vault dashboard widget for Cipher.

Displays a time-based greeting, search bar, and a clean credential list.
Credentials are rendered as borderless rows (not cards) with hover actions.
Clicking a row transitions to the DetailView.
"""

from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QScrollArea, QApplication,
    QStackedWidget, QSizePolicy, QComboBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from models import Session
from models.vault import VaultEntry
from services.crypto import decrypt_data
from services.password_generator import calculate_password_strength
from gui.detail_view import DetailView
from gui.add_entry_dialog import AddEntryDialog
from gui.theme import ThemeManager


class CredentialRow(QFrame):
    """A single credential row in the vault list.

    Displays: status dot/icon | title + username | last used | arrow.
    Hover reveals copy actions. Click navigates to detail view.
    """

    clicked = pyqtSignal(int)

    def __init__(self, entry_id: int, title: str, username: str,
                 strength_score: int = 100, last_used: str = "", category: str = "login"):
        super().__init__()
        self.entry_id = entry_id
        self.setProperty("class", "credential-row")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(60)
        self._init_ui(title, username, strength_score, last_used, category)

    def _init_ui(self, title: str, username: str,
                 strength_score: int, last_used: str, category: str):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(12)

        icon_str = "●"
        c = ThemeManager.colors()
        color = c['text_secondary']
        font_size = 14
        
        if category == "login":
            icon_str = "●"
            font_size = 10
            if strength_score >= 60:
                color = c['success']
            elif strength_score >= 40:
                color = c['warning']
            else:
                color = c['danger']
        elif category == "card":
            icon_str = "💳"
        elif category == "note":
            icon_str = "📝"
        elif category == "identity":
            icon_str = "👤"

        dot = QLabel(icon_str)
        dot.setStyleSheet(f"color: {color}; font-size: {font_size}px;")
        dot.setFixedWidth(20)
        dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(dot)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        text_layout.setContentsMargins(0, 0, 0, 0)

        title_lbl = QLabel(title)
        title_lbl.setProperty("class", "credential-name")
        text_layout.addWidget(title_lbl)

        display_user = username
        if category == 'note':
            display_user = "Secure Note"
            
        user_lbl = QLabel(display_user if display_user else "")
        user_lbl.setProperty("class", "muted")
        user_lbl.setStyleSheet(f"color: {c['text_muted']}; font-size: 13px;")
        text_layout.addWidget(user_lbl)

        layout.addLayout(text_layout)
        layout.addStretch()

        if last_used:
            time_lbl = QLabel(last_used)
            time_lbl.setProperty("class", "metadata")
            layout.addWidget(time_lbl)

        arrow = QLabel("→")
        arrow.setStyleSheet(f"color: {c['text_muted']}; font-size: 14px;")
        arrow.setFixedWidth(16)
        layout.addWidget(arrow)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.entry_id)
        super().mousePressEvent(event)


class VaultWidget(QWidget):
    """Dashboard widget with greeting, search, credential list, and detail view."""

    def __init__(self, user_id: int, vault_key: bytes, parent=None):
        super().__init__(parent)
        self.user_id = user_id
        self.vault_key = vault_key
        self.entries_data = []  # All decrypted entries
        self.current_filter = None

        self._init_ui()
        self.load_entries()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Stacked content
        self.stack = QStackedWidget()

        # ── List View ──────────────────────────────────────────────────
        list_page = QWidget()
        list_layout = QVBoxLayout(list_page)
        list_layout.setContentsMargins(32, 28, 32, 28)
        list_layout.setSpacing(0)

        # Greeting
        hour = datetime.now().hour
        if hour < 12:
            greeting = "Good morning"
        elif hour < 17:
            greeting = "Good afternoon"
        else:
            greeting = "Good evening"

        greeting_lbl = QLabel(greeting)
        greeting_lbl.setProperty("class", "greeting")
        list_layout.addWidget(greeting_lbl)
        list_layout.addSpacing(6)

        self.status_lbl = QLabel("Your vault is secure.")
        self.status_lbl.setProperty("class", "muted")
        list_layout.addWidget(self.status_lbl)
        list_layout.addSpacing(24)

        # Search bar
        self.search_input = QLineEdit()
        self.search_input.setProperty("class", "search")
        self.search_input.setPlaceholderText("🔍  Search your vault...")
        self.search_input.textChanged.connect(self._filter_entries)
        list_layout.addWidget(self.search_input)
        list_layout.addSpacing(24)

        # Section heading with sort
        section_row = QHBoxLayout()
        self.section_label = QLabel("Recent")
        self.section_label.setProperty("class", "section")
        section_row.addWidget(self.section_label)
        section_row.addStretch()

        sort_lbl = QLabel("Sort:")
        sort_lbl.setProperty("class", "metadata")
        section_row.addWidget(sort_lbl)

        self.sort_combo = QComboBox()
        self.sort_combo.addItems(["Newest", "Alphabetical", "Strength ↑", "Last Used"])
        self.sort_combo.setFixedWidth(120)
        self.sort_combo.currentIndexChanged.connect(
            lambda: self._render_filtered_list()
        )
        section_row.addWidget(self.sort_combo)

        list_layout.addLayout(section_row)
        list_layout.addSpacing(12)

        # Scrollable credential list
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.list_widget = QWidget()
        self.list_layout = QVBoxLayout(self.list_widget)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.list_layout.setSpacing(0)
        self.list_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll.setWidget(self.list_widget)

        list_layout.addWidget(scroll)
        list_layout.addSpacing(16)

        # Add Item button
        btn_add = QPushButton("+ Add Item")
        btn_add.setProperty("class", "outline")
        btn_add.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_add.setFixedWidth(120)
        btn_add.clicked.connect(self._open_add_dialog)
        list_layout.addWidget(btn_add, alignment=Qt.AlignmentFlag.AlignRight)

        self.stack.addWidget(list_page)

        # ── Detail View ────────────────────────────────────────────────
        self.detail_view = DetailView(self.user_id, self.vault_key)
        self.detail_view.back_requested.connect(self._show_list)
        self.detail_view.entry_deleted.connect(self._on_entry_deleted)
        self.detail_view.edit_requested.connect(self._open_edit_dialog)
        self.stack.addWidget(self.detail_view)

        main_layout.addWidget(self.stack)

    def load_entries(self):
        """Loads and decrypts all user credentials."""
        self.entries_data = []

        with Session() as session:
            entries = (
                session.query(VaultEntry)
                .filter_by(user_id=self.user_id)
                .order_by(VaultEntry.created_at.desc())
                .all()
            )

            for e in entries:
                try:
                    title = decrypt_data(e.encrypted_title, e.nonce_title, self.vault_key)
                    username = (
                        decrypt_data(e.encrypted_username, e.nonce_username, self.vault_key)
                        if e.encrypted_username else ""
                    )
                    pwd = decrypt_data(e.encrypted_password, e.nonce_password, self.vault_key)
                    strength = calculate_password_strength(pwd)

                    # Format last used
                    last_used_str = ""
                    if e.last_used_at:
                        delta = datetime.utcnow() - e.last_used_at
                        if delta.days > 0:
                            last_used_str = f"Last used {delta.days}d"
                        elif delta.seconds >= 3600:
                            last_used_str = f"Last used {delta.seconds // 3600}h"
                        else:
                            last_used_str = f"Last used {max(1, delta.seconds // 60)}m"

                    self.entries_data.append({
                        'id': e.id,
                        'title': title,
                        'username': username,
                        'strength_score': strength['score'],
                        'last_used': last_used_str,
                        'category': getattr(e, 'category', 'login') or 'login',
                        'is_favorite': getattr(e, 'is_favorite', False) or False,
                        'last_used_at': e.last_used_at,
                    })
                except Exception:
                    pass

        self._render_filtered_list()

    def apply_filter(self, filter_type):
        """Apply a navigation filter and re-render the list."""
        self.current_filter = filter_type
        self._show_list()
        self._render_filtered_list()

    def _get_filtered_data(self):
        """Filter entries based on current navigation selection."""
        data = self.entries_data

        if self.current_filter is None:
            # All items — show as-is
            self.section_label.setText("Recent")
            return data
        elif self.current_filter == 'favorites':
            self.section_label.setText("Favorites")
            return [e for e in data if e.get('is_favorite')]
        elif self.current_filter == 'recent':
            self.section_label.setText("Recently Used")
            # Sort by last_used_at descending
            sorted_data = sorted(
                [e for e in data if e.get('last_used_at')],
                key=lambda x: x['last_used_at'] or datetime.min,
                reverse=True
            )
            return sorted_data[:20]
        elif self.current_filter in ('login', 'card', 'note', 'identity'):
            labels = {
                'login': 'Logins',
                'card': 'Cards',
                'note': 'Secure Notes',
                'identity': 'Identities',
            }
            self.section_label.setText(labels.get(self.current_filter, 'Items'))
            return [e for e in data if e.get('category') == self.current_filter]

        return data

    def _sort_data(self, data: list) -> list:
        """Sort entries based on the sort dropdown selection."""
        idx = self.sort_combo.currentIndex()
        if idx == 1:  # Alphabetical
            return sorted(data, key=lambda e: e['title'].lower())
        elif idx == 2:  # Strength ascending (weakest first)
            return sorted(data, key=lambda e: e.get('strength_score', 100))
        elif idx == 3:  # Last Used descending
            return sorted(
                data,
                key=lambda e: e.get('last_used_at') or datetime.min,
                reverse=True,
            )
        # Default: Newest (already in created_at desc order)
        return data

    def _render_filtered_list(self):
        """Render the credential list with current filter and sort applied."""
        data = self._get_filtered_data()

        # Update section label with count
        count = len(data)
        current_text = self.section_label.text().split(" (")[0]  # strip old count
        self.section_label.setText(f"{current_text} ({count})")

        # Apply search on top of filter
        query = self.search_input.text().strip().lower()
        if query:
            data = [
                e for e in data
                if query in e['title'].lower() or query in e['username'].lower()
            ]

        # Apply sorting
        data = self._sort_data(data)

        self._render_rows(data)

    def _render_rows(self, data_list):
        """Render credential rows from a data list."""
        # Clear existing rows
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not data_list:
            empty_container = QWidget()
            empty_layout = QVBoxLayout(empty_container)
            empty_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty_layout.setContentsMargins(0, 60, 0, 0)

            icon_lbl = QLabel("◈")
            icon_lbl.setStyleSheet(
                "font-size: 40px; color: #252930;"
            )
            icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty_layout.addWidget(icon_lbl)

            empty_title = QLabel("No credentials yet")
            empty_title.setStyleSheet(
                "font-size: 16px; font-weight: 500; color: #5F6570;"
            )
            empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty_layout.addWidget(empty_title)

            empty_hint = QLabel(
                'Click "+ Add Item" below to store your first credential.'
            )
            empty_hint.setProperty("class", "muted")
            empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty_layout.addWidget(empty_hint)

            self.list_layout.addWidget(empty_container)
            return

        for item in data_list:
            row = CredentialRow(
                item['id'],
                item['title'],
                item['username'],
                item.get('strength_score', 100),
                item.get('last_used', ''),
                item.get('category', 'login')
            )
            row.clicked.connect(self._show_detail)
            self.list_layout.addWidget(row)

    def _filter_entries(self, text: str):
        """Search filter on top of current navigation filter."""
        self._render_filtered_list()

    def _show_detail(self, entry_id: int):
        """Navigate to detail view for the given entry instantly."""
        self.detail_view.load_entry(entry_id)
        self.stack.setCurrentIndex(1)

    def _show_list(self):
        """Return to the credential list instantly."""
        self.stack.setCurrentIndex(0)

    def _on_entry_deleted(self):
        """Handle entry deletion from detail view."""
        self._show_list()
        self.load_entries()

    def _open_add_dialog(self):
        """Open the add credential dialog."""
        dialog = AddEntryDialog(self.user_id, self.vault_key, self)
        dialog.entry_saved.connect(self.load_entries)
        dialog.exec()

    def _open_edit_dialog(self, entry_id: int):
        """Open the edit credential dialog."""
        dialog = AddEntryDialog(self.user_id, self.vault_key, self, edit_entry_id=entry_id)
        dialog.entry_saved.connect(lambda: self._refresh_after_edit(entry_id))
        dialog.exec()

    def _refresh_after_edit(self, entry_id: int):
        """Reload entries and re-open detail view after edit."""
        self.load_entries()
        self.detail_view.load_entry(entry_id)
