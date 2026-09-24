"""Credential detail view for Cipher.

Shows the full credential information with masked password, copy actions,
metadata, and edit/delete controls. Designed as the right-panel detail
that replaces the list when a credential is selected.
"""

from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QTextEdit, QPushButton, QFrame, QApplication, QMessageBox,
    QScrollArea
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QUrl
from PyQt6.QtGui import QDesktopServices
from models import Session
from models.vault import VaultEntry
from services.crypto import decrypt_data
from services.password_generator import calculate_password_strength
from gui.theme import ThemeManager


class DetailView(QWidget):
    """Full credential detail view matching the 'Quiet Security' design spec."""

    back_requested = pyqtSignal()
    entry_deleted = pyqtSignal()
    edit_requested = pyqtSignal(int)  # entry_id

    def __init__(self, user_id: int, vault_key: bytes, parent=None):
        super().__init__(parent)
        self.user_id = user_id
        self.vault_key = vault_key
        self.current_entry_id = None
        self.clipboard_timer = QTimer(self)
        self.clipboard_timer.setSingleShot(True)
        self.clipboard_timer.timeout.connect(self._clear_clipboard)

        self._init_ui()

    def _init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 24, 32, 32)
        layout.setSpacing(0)

        # ── Back button ───────────────────────────────────────────────
        btn_back = QPushButton("← Back")
        btn_back.setProperty("class", "link")
        btn_back.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_back.clicked.connect(self.back_requested.emit)
        btn_back.setFixedWidth(60)
        layout.addWidget(btn_back)
        layout.addSpacing(20)

        # ── Title & Domain ────────────────────────────────────────────
        self.title_lbl = QLabel()
        self.title_lbl.setProperty("class", "title")
        layout.addWidget(self.title_lbl)
        layout.addSpacing(4)

        self.domain_lbl = QLabel()
        self.domain_lbl.setProperty("class", "muted")
        layout.addWidget(self.domain_lbl)
        layout.addSpacing(28)

        # ── Stack for category fields ─────────────────────────────────
        from PyQt6.QtWidgets import QStackedWidget
        self.field_stack = QStackedWidget()
        layout.addWidget(self.field_stack)

        # PAGE 0: LOGIN
        self.page_login = QWidget()
        login_layout = QVBoxLayout(self.page_login)
        login_layout.setContentsMargins(0,0,0,0)
        login_layout.setSpacing(0)

        section_lbl = QLabel("LOGIN DETAILS")
        section_lbl.setProperty("class", "nav-section")
        login_layout.addWidget(section_lbl)
        login_layout.addSpacing(16)

        u_lbl = QLabel("Username")
        u_lbl.setProperty("class", "metadata")
        login_layout.addWidget(u_lbl)
        login_layout.addSpacing(4)

        u_row = QHBoxLayout()
        u_row.setSpacing(8)
        self.user_input = QLineEdit()
        self.user_input.setReadOnly(True)
        self.btn_copy_user = QPushButton("Copy")
        self.btn_copy_user.setProperty("class", "small-outline")
        self.btn_copy_user.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_copy_user.clicked.connect(lambda: self._copy_field(self.user_input.text(), self.btn_copy_user))
        u_row.addWidget(self.user_input)
        u_row.addWidget(self.btn_copy_user)
        login_layout.addLayout(u_row)
        login_layout.addSpacing(16)

        p_lbl = QLabel("Password")
        p_lbl.setProperty("class", "metadata")
        login_layout.addWidget(p_lbl)
        login_layout.addSpacing(4)

        p_row = QHBoxLayout()
        p_row.setSpacing(8)
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd_input.setReadOnly(True)

        self.btn_show_pwd = QPushButton("Show")
        self.btn_show_pwd.setProperty("class", "small-outline")
        self.btn_show_pwd.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_show_pwd.clicked.connect(self._toggle_password)

        self.btn_copy_pwd = QPushButton("Copy")
        self.btn_copy_pwd.setProperty("class", "small-outline")
        self.btn_copy_pwd.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_copy_pwd.clicked.connect(lambda: self._copy_field(self.pwd_input.text(), self.btn_copy_pwd))

        p_row.addWidget(self.pwd_input)
        p_row.addWidget(self.btn_show_pwd)
        p_row.addWidget(self.btn_copy_pwd)
        login_layout.addLayout(p_row)
        login_layout.addSpacing(24)

        login_layout.addWidget(self._separator())
        login_layout.addSpacing(20)

        str_lbl = QLabel("Password strength")
        str_lbl.setProperty("class", "metadata")
        login_layout.addWidget(str_lbl)
        login_layout.addSpacing(4)

        self.strength_lbl = QLabel()
        self.strength_lbl.setStyleSheet("font-size: 14px; font-weight: 500;")
        login_layout.addWidget(self.strength_lbl)
        login_layout.addSpacing(20)

        login_layout.addWidget(self._separator())
        login_layout.addSpacing(20)

        self.pwd_age_lbl = QLabel()
        self.pwd_age_lbl.setProperty("class", "metadata")
        login_layout.addWidget(self.pwd_age_lbl)
        login_layout.addSpacing(20)

        login_layout.addWidget(self._separator())
        login_layout.addSpacing(20)

        url_label = QLabel("Website")
        url_label.setProperty("class", "metadata")
        login_layout.addWidget(url_label)
        login_layout.addSpacing(4)

        url_row = QHBoxLayout()
        url_row.setSpacing(8)
        self.url_input = QLineEdit()
        self.url_input.setReadOnly(True)
        self.btn_copy_url = QPushButton("Copy")
        self.btn_copy_url.setProperty("class", "small-outline")
        self.btn_copy_url.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_copy_url.clicked.connect(lambda: self._copy_field(self.url_input.text(), self.btn_copy_url))
        self.btn_open_url = QPushButton("Open")
        self.btn_open_url.setProperty("class", "small-outline")
        self.btn_open_url.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_open_url.clicked.connect(self._open_in_browser)
        url_row.addWidget(self.url_input)
        url_row.addWidget(self.btn_copy_url)
        url_row.addWidget(self.btn_open_url)
        login_layout.addLayout(url_row)
        login_layout.addSpacing(20)

        self.field_stack.addWidget(self.page_login)

        # PAGE 1: CARD
        self.page_card = QWidget()
        card_layout = QVBoxLayout(self.page_card)
        card_layout.setContentsMargins(0,0,0,0)
        card_layout.setSpacing(0)
        
        card_sec = QLabel("CARD DETAILS")
        card_sec.setProperty("class", "nav-section")
        card_layout.addWidget(card_sec)
        card_layout.addSpacing(16)

        cname_lbl = QLabel("Cardholder Name")
        cname_lbl.setProperty("class", "metadata")
        card_layout.addWidget(cname_lbl)
        card_layout.addSpacing(4)

        cname_row = QHBoxLayout()
        self.card_name_input = QLineEdit()
        self.card_name_input.setReadOnly(True)
        self.btn_copy_cname = QPushButton("Copy")
        self.btn_copy_cname.setProperty("class", "small-outline")
        self.btn_copy_cname.clicked.connect(lambda: self._copy_field(self.card_name_input.text(), self.btn_copy_cname))
        cname_row.addWidget(self.card_name_input)
        cname_row.addWidget(self.btn_copy_cname)
        card_layout.addLayout(cname_row)
        card_layout.addSpacing(16)

        cnum_lbl = QLabel("Card Number")
        cnum_lbl.setProperty("class", "metadata")
        card_layout.addWidget(cnum_lbl)
        card_layout.addSpacing(4)
        cnum_row = QHBoxLayout()
        self.card_num_input = QLineEdit()
        self.card_num_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.card_num_input.setReadOnly(True)
        
        self.btn_show_card = QPushButton("Show")
        self.btn_show_card.setProperty("class", "small-outline")
        self.btn_show_card.clicked.connect(self._toggle_card)

        self.btn_copy_cnum = QPushButton("Copy")
        self.btn_copy_cnum.setProperty("class", "small-outline")
        self.btn_copy_cnum.clicked.connect(lambda: self._copy_field(self.card_num_input.text(), self.btn_copy_cnum))
        cnum_row.addWidget(self.card_num_input)
        cnum_row.addWidget(self.btn_show_card)
        cnum_row.addWidget(self.btn_copy_cnum)
        card_layout.addLayout(cnum_row)
        card_layout.addSpacing(16)
        
        cc_grid = QHBoxLayout()
        
        col_exp = QVBoxLayout()
        e_lbl = QLabel("Expiration")
        e_lbl.setProperty("class", "metadata")
        self.card_exp_input = QLineEdit()
        self.card_exp_input.setReadOnly(True)
        col_exp.addWidget(e_lbl)
        col_exp.addWidget(self.card_exp_input)
        cc_grid.addLayout(col_exp)

        col_cvv = QVBoxLayout()
        c_lbl = QLabel("CVV")
        c_lbl.setProperty("class", "metadata")
        self.card_cvv_input = QLineEdit()
        self.card_cvv_input.setReadOnly(True)
        self.card_cvv_input.setEchoMode(QLineEdit.EchoMode.Password)
        col_cvv.addWidget(c_lbl)
        col_cvv.addWidget(self.card_cvv_input)
        cc_grid.addLayout(col_cvv)
        
        col_pin = QVBoxLayout()
        pi_lbl = QLabel("PIN")
        pi_lbl.setProperty("class", "metadata")
        self.card_pin_input = QLineEdit()
        self.card_pin_input.setReadOnly(True)
        self.card_pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        col_pin.addWidget(pi_lbl)
        col_pin.addWidget(self.card_pin_input)
        cc_grid.addLayout(col_pin)

        card_layout.addLayout(cc_grid)
        card_layout.addSpacing(20)
        self.field_stack.addWidget(self.page_card)

        # PAGE 2: SECURE NOTE
        self.page_note = QWidget()
        note_layout = QVBoxLayout(self.page_note)
        note_layout.setContentsMargins(0,0,0,0)
        
        n_sec = QLabel("NOTE DETAILS")
        n_sec.setProperty("class", "nav-section")
        note_layout.addWidget(n_sec)
        note_layout.addSpacing(16)
        self.field_stack.addWidget(self.page_note)

        # PAGE 3: IDENTITY
        self.page_id = QWidget()
        id_layout = QVBoxLayout(self.page_id)
        id_layout.setContentsMargins(0,0,0,0)
        id_layout.setSpacing(0)
        
        id_sec = QLabel("IDENTITY DETAILS")
        id_sec.setProperty("class", "nav-section")
        id_layout.addWidget(id_sec)
        id_layout.addSpacing(16)
        
        # Name
        ifn_lbl = QLabel("Full Name")
        ifn_lbl.setProperty("class", "metadata")
        id_layout.addWidget(ifn_lbl)
        id_layout.addSpacing(4)
        ifn_row = QHBoxLayout()
        self.id_name_input = QLineEdit()
        self.id_name_input.setReadOnly(True)
        self.btn_copy_ifn = QPushButton("Copy")
        self.btn_copy_ifn.setProperty("class", "small-outline")
        self.btn_copy_ifn.clicked.connect(lambda: self._copy_field(self.id_name_input.text(), self.btn_copy_ifn))
        ifn_row.addWidget(self.id_name_input)
        ifn_row.addWidget(self.btn_copy_ifn)
        id_layout.addLayout(ifn_row)
        id_layout.addSpacing(16)
        
        # Email
        iem_lbl = QLabel("Email")
        iem_lbl.setProperty("class", "metadata")
        id_layout.addWidget(iem_lbl)
        id_layout.addSpacing(4)
        iem_row = QHBoxLayout()
        self.id_email_input = QLineEdit()
        self.id_email_input.setReadOnly(True)
        self.btn_copy_iem = QPushButton("Copy")
        self.btn_copy_iem.setProperty("class", "small-outline")
        self.btn_copy_iem.clicked.connect(lambda: self._copy_field(self.id_email_input.text(), self.btn_copy_iem))
        iem_row.addWidget(self.id_email_input)
        iem_row.addWidget(self.btn_copy_iem)
        id_layout.addLayout(iem_row)
        id_layout.addSpacing(16)
        
        # Phone
        iph_lbl = QLabel("Phone")
        iph_lbl.setProperty("class", "metadata")
        id_layout.addWidget(iph_lbl)
        id_layout.addSpacing(4)
        iph_row = QHBoxLayout()
        self.id_phone_input = QLineEdit()
        self.id_phone_input.setReadOnly(True)
        self.btn_copy_iph = QPushButton("Copy")
        self.btn_copy_iph.setProperty("class", "small-outline")
        self.btn_copy_iph.clicked.connect(lambda: self._copy_field(self.id_phone_input.text(), self.btn_copy_iph))
        iph_row.addWidget(self.id_phone_input)
        iph_row.addWidget(self.btn_copy_iph)
        id_layout.addLayout(iph_row)
        id_layout.addSpacing(16)

        # SSN
        iss_lbl = QLabel("SSN / ID Number")
        iss_lbl.setProperty("class", "metadata")
        id_layout.addWidget(iss_lbl)
        id_layout.addSpacing(4)
        iss_row = QHBoxLayout()
        self.id_ssn_input = QLineEdit()
        self.id_ssn_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.id_ssn_input.setReadOnly(True)
        
        self.btn_show_ssn = QPushButton("Show")
        self.btn_show_ssn.setProperty("class", "small-outline")
        self.btn_show_ssn.clicked.connect(self._toggle_ssn)
        
        self.btn_copy_iss = QPushButton("Copy")
        self.btn_copy_iss.setProperty("class", "small-outline")
        self.btn_copy_iss.clicked.connect(lambda: self._copy_field(self.id_ssn_input.text(), self.btn_copy_iss))
        iss_row.addWidget(self.id_ssn_input)
        iss_row.addWidget(self.btn_show_ssn)
        iss_row.addWidget(self.btn_copy_iss)
        id_layout.addLayout(iss_row)
        id_layout.addSpacing(16)

        # Address
        iad_lbl = QLabel("Address")
        iad_lbl.setProperty("class", "metadata")
        id_layout.addWidget(iad_lbl)
        id_layout.addSpacing(4)
        self.id_addr_input = QTextEdit()
        self.id_addr_input.setReadOnly(True)
        self.id_addr_input.setMaximumHeight(50)
        id_layout.addWidget(self.id_addr_input)
        id_layout.addSpacing(20)

        self.field_stack.addWidget(self.page_id)
        
        # ── COMMON FOOTER ─────────────────────────────────────────────
        layout.addWidget(self._separator())
        layout.addSpacing(20)

        # Notes
        notes_lbl = QLabel("Notes")
        notes_lbl.setProperty("class", "metadata")
        layout.addWidget(notes_lbl)
        layout.addSpacing(4)

        self.notes_display = QLabel()
        self.notes_display.setWordWrap(True)
        self.notes_display.setStyleSheet("font-size: 13px;")
        layout.addWidget(self.notes_display)
        layout.addSpacing(20)

        layout.addWidget(self._separator())
        layout.addSpacing(20)

        # Metadata
        self.created_lbl = QLabel()
        self.created_lbl.setProperty("class", "metadata")
        layout.addWidget(self.created_lbl)
        layout.addSpacing(4)

        self.modified_lbl = QLabel()
        self.modified_lbl.setProperty("class", "metadata")
        layout.addWidget(self.modified_lbl)
        layout.addSpacing(28)

        # ── Actions ───────────────────────────────────────────────────
        action_row = QHBoxLayout()

        self.btn_favorite = QPushButton("☆  Favorite")
        self.btn_favorite.setProperty("class", "small-outline")
        self.btn_favorite.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_favorite.clicked.connect(self._toggle_favorite)
        action_row.addWidget(self.btn_favorite)

        action_row.addStretch()

        btn_edit = QPushButton("Edit")
        btn_edit.setProperty("class", "outline")
        btn_edit.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_edit.clicked.connect(self._handle_edit)
        action_row.addWidget(btn_edit)

        action_row.addSpacing(8)

        btn_delete = QPushButton("Delete")
        btn_delete.setProperty("class", "danger")
        btn_delete.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_delete.clicked.connect(self._handle_delete)
        action_row.addWidget(btn_delete)

        layout.addLayout(action_row)
        layout.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)

    def _toggle_card(self):
        if self.card_num_input.echoMode() == QLineEdit.EchoMode.Password:
            self.card_num_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.card_cvv_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.card_pin_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_show_card.setText("Hide")
        else:
            self.card_num_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.card_cvv_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.card_pin_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_show_card.setText("Show")

    def _toggle_ssn(self):
        if self.id_ssn_input.echoMode() == QLineEdit.EchoMode.Password:
            self.id_ssn_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_show_ssn.setText("Hide")
        else:
            self.id_ssn_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_show_ssn.setText("Show")
    def _separator(self) -> QFrame:
        sep = QFrame()
        sep.setProperty("class", "separator")
        sep.setFixedHeight(1)
        return sep

    def load_entry(self, entry_id: int):
        self.current_entry_id = entry_id

        self.pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.btn_show_pwd.setText("Show")
        self.card_num_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.card_cvv_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.card_pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.btn_show_card.setText("Show")
        self.id_ssn_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.btn_show_ssn.setText("Show")

        import json
        with Session() as session:
            entry = session.query(VaultEntry).filter_by(
                id=entry_id, user_id=self.user_id
            ).first()
            if not entry:
                return

            try:
                cat_map_rev = {'login': 0, 'card': 1, 'note': 2, 'identity': 3}
                idx = cat_map_rev.get(entry.category, 0)
                self.field_stack.setCurrentIndex(idx)

                title = decrypt_data(entry.encrypted_title, entry.nonce_title, self.vault_key)
                self.title_lbl.setText(title)
                
                self.domain_lbl.setText(entry.category.title())

                username = ""
                if entry.encrypted_username:
                    username = decrypt_data(entry.encrypted_username, entry.nonce_username, self.vault_key)
                
                password = ""
                if entry.encrypted_password:
                    password = decrypt_data(entry.encrypted_password, entry.nonce_password, self.vault_key)
                
                url = ""
                if entry.encrypted_url:
                    url = decrypt_data(entry.encrypted_url, entry.nonce_url, self.vault_key)

                notes_json = ""
                if entry.encrypted_notes:
                    notes_json = decrypt_data(entry.encrypted_notes, entry.nonce_notes, self.vault_key)
                    
                extra_data = {}
                if notes_json:
                    try:
                        extra_data = json.loads(notes_json)
                    except Exception:
                        extra_data = {"notes": notes_json}

                actual_notes = extra_data.get("notes", "")
                self.notes_display.setText(actual_notes if actual_notes else "No notes")

                if entry.category == 'login':
                    self.user_input.setText(username)
                    self.pwd_input.setText(password)
                    self.url_input.setText(url)
                    domain = url.replace("https://", "").replace("http://", "").split("/")[0] if url else ""
                    self.domain_lbl.setText(domain)
                    
                    strength = calculate_password_strength(password)
                    label = strength['label']
                    colors = {
                        'Weak': '#E5484D',
                        'Fair': '#E5A63E',
                        'Good': '#2D7FF9',
                        'Strong': '#30A46C',
                        'Very Strong': '#30A46C'
                    }
                    c = colors.get(label, '#9298A3')
                    self.strength_lbl.setText(label)
                    self.strength_lbl.setStyleSheet(f"color: {c}; font-size: 14px; font-weight: 500;")
                    
                    if entry.last_used_at:
                        self.pwd_age_lbl.setText(f"Last used: {entry.last_used_at.strftime('%b %d, %Y')}")
                    else:
                        self.pwd_age_lbl.setText("Never used")
                elif entry.category == 'card':
                    self.card_name_input.setText(username)
                    self.card_num_input.setText(password)
                    self.card_exp_input.setText(extra_data.get("exp", ""))
                    self.card_cvv_input.setText(extra_data.get("cvv", ""))
                    self.card_pin_input.setText(extra_data.get("pin", ""))
                elif entry.category == 'identity':
                    self.id_name_input.setText(username)
                    self.id_ssn_input.setText(password)
                    self.id_email_input.setText(extra_data.get("email", ""))
                    self.id_phone_input.setText(extra_data.get("phone", ""))
                    self.id_addr_input.setText(extra_data.get("address", ""))
                    
                if entry.created_at:
                    self.created_lbl.setText(f"Created  {entry.created_at.strftime('%d %b %Y')}")
                if entry.updated_at:
                    self.modified_lbl.setText(f"Last modified  {entry.updated_at.strftime('%d %b %Y')}")

                is_fav = getattr(entry, 'is_favorite', False) or False
                self._is_favorite = is_fav
                self.btn_favorite.setText("★  Favorited" if is_fav else "☆  Favorite")
                self.btn_favorite.setProperty("class", "primary" if is_fav else "small-outline")
                self.btn_favorite.style().unpolish(self.btn_favorite)
                self.btn_favorite.style().polish(self.btn_favorite)

                entry.last_used_at = datetime.utcnow()
                session.commit()
            except Exception:
                self.title_lbl.setText("Decryption Error")


    def _toggle_password(self):
        if self.pwd_input.echoMode() == QLineEdit.EchoMode.Password:
            self.pwd_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_show_pwd.setText("Hide")
        else:
            self.pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_show_pwd.setText("Show")

    def _copy_field(self, text: str, button: QPushButton):
        if not text:
            return
        clipboard = QApplication.clipboard()
        clipboard.setText(text)

        orig = button.text()
        button.setText("✓")
        QTimer.singleShot(2000, lambda: button.setText(orig))

        # Auto-clear clipboard after 30 seconds
        self.clipboard_timer.start(30000)

    def _clear_clipboard(self):
        QApplication.clipboard().clear()

    def _open_in_browser(self):
        """Open the credential's URL in the default browser."""
        url = self.url_input.text()
        if not url:
            return
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        QDesktopServices.openUrl(QUrl(url))

    def _toggle_favorite(self):
        """Toggle the favorite status of the current entry."""
        if not self.current_entry_id:
            return

        with Session() as session:
            entry = session.query(VaultEntry).filter_by(
                id=self.current_entry_id, user_id=self.user_id
            ).first()
            if entry:
                new_fav = not (getattr(entry, 'is_favorite', False) or False)
                entry.is_favorite = new_fav
                session.commit()
                self._is_favorite = new_fav
                self.btn_favorite.setText(
                    "★  Favorited" if new_fav else "☆  Favorite"
                )

    def _handle_edit(self):
        if self.current_entry_id:
            self.edit_requested.emit(self.current_entry_id)

    def _handle_delete(self):
        if not self.current_entry_id:
            return

        confirm = QMessageBox.question(
            self,
            "Delete Credential",
            "Are you sure you want to permanently delete this credential?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if confirm == QMessageBox.StandardButton.Yes:
            with Session() as session:
                entry = session.query(VaultEntry).filter_by(
                    id=self.current_entry_id, user_id=self.user_id
                ).first()
                if entry:
                    session.delete(entry)
                    session.commit()

            self.current_entry_id = None
            self.entry_deleted.emit()
