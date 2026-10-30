"""Dialog for adding or editing a vault credential in Cipher.

'Almost boring' — clean form with minimal visual noise.
Supports both create and edit modes via the optional edit_entry_id parameter.
"""

import json
import secrets
import string
import traceback
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QTextEdit, QPushButton, QSlider, QCheckBox, QFrame,
    QMessageBox, QComboBox, QProgressBar, QWidget, QStackedWidget
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from models import Session
from models.vault import VaultEntry
from services.crypto import encrypt_data, decrypt_data
from services.password_generator import (
    calculate_password_strength,
    generate_passphrase,
    generate_random_password,
)
from services.breach_check import BreachChecker
from gui.theme import ThemeManager


class AddEntryDialog(QDialog):
    """Modal dialog for creating or editing a vault credential."""

    entry_saved = pyqtSignal()

    def __init__(self, user_id: int, vault_key: bytes, parent=None,
                 edit_entry_id: int = None):
        super().__init__(parent)
        self.user_id = user_id
        self.vault_key = vault_key
        self.edit_entry_id = edit_entry_id
        self._breach_checker = BreachChecker()
        self._breach_debounce = QTimer()
        self._breach_debounce.setSingleShot(True)
        self._breach_debounce.setInterval(800)
        self._breach_debounce.timeout.connect(self._trigger_breach_check)
        self._init_ui()

        if edit_entry_id:
            self._load_entry_data()

    def _cleanup(self):
        """Clean up background threads before dialog destruction."""
        try:
            self._breach_debounce.stop()
            self._breach_checker.cancel()
        except Exception:
            pass

    def accept(self):
        self._cleanup()
        super().accept()

    def reject(self):
        self._cleanup()
        super().reject()

    def closeEvent(self, event):
        self._cleanup()
        super().closeEvent(event)


    def _init_ui(self):
        is_edit = self.edit_entry_id is not None
        self.setWindowTitle("Edit Credential" if is_edit else "Add Item")
        self.setFixedWidth(460)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(28, 24, 28, 24)

        self.header = QLabel("Edit Credential" if is_edit else "Add Login")
        self.header.setProperty("class", "section")
        layout.addWidget(self.header)
        layout.addSpacing(4)

        # Category
        cat_lbl = QLabel("Category")
        cat_lbl.setProperty("class", "metadata")
        self.cat_combo = QComboBox()
        self.cat_combo.addItems(["Login", "Card", "Secure Note", "Identity"])
        self.cat_combo.currentIndexChanged.connect(self._on_category_changed)
        layout.addWidget(cat_lbl)
        layout.addWidget(self.cat_combo)

        # Title (Common to all)
        self.title_lbl = QLabel("Name")
        self.title_lbl.setProperty("class", "metadata")
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("Google")
        layout.addWidget(self.title_lbl)
        layout.addWidget(self.title_input)

        # Stacked Widget for fields
        self.field_stack = QStackedWidget()
        layout.addWidget(self.field_stack)

        # ==========================================
        # PAGE 0: LOGIN
        # ==========================================
        self.page_login = QWidget()
        login_layout = QVBoxLayout(self.page_login)
        login_layout.setContentsMargins(0, 0, 0, 0)
        login_layout.setSpacing(14)

        user_lbl = QLabel("Username")
        user_lbl.setProperty("class", "metadata")
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("user@gmail.com")
        login_layout.addWidget(user_lbl)
        login_layout.addWidget(self.user_input)

        pwd_lbl = QLabel("Password")
        pwd_lbl.setProperty("class", "metadata")
        login_layout.addWidget(pwd_lbl)

        pwd_row = QHBoxLayout()
        pwd_row.setSpacing(8)
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd_input.setPlaceholderText("••••••••••••••••")
        self.pwd_input.textChanged.connect(self._update_strength)
        self.pwd_input.textChanged.connect(self._schedule_breach_check)

        self.btn_toggle_pwd = QPushButton("👁")
        self.btn_toggle_pwd.setProperty("class", "small-outline")
        self.btn_toggle_pwd.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle_pwd.setFixedWidth(36)
        self.btn_toggle_pwd.clicked.connect(self._toggle_password_visibility)

        pwd_row.addWidget(self.pwd_input)
        pwd_row.addWidget(self.btn_toggle_pwd)
        login_layout.addLayout(pwd_row)

        btn_gen = QPushButton("Generate password")
        btn_gen.setProperty("class", "link")
        btn_gen.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_gen.clicked.connect(self._toggle_generator)
        login_layout.addWidget(btn_gen)

        self.gen_frame = QFrame()
        self.gen_frame.setProperty("class", "card")
        gen_layout = QVBoxLayout(self.gen_frame)
        gen_layout.setContentsMargins(14, 14, 14, 14)
        gen_layout.setSpacing(10)

        mode_row = QHBoxLayout()
        mode_lbl = QLabel("Mode")
        mode_lbl.setProperty("class", "metadata")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Random Password", "Passphrase"])
        self.mode_combo.currentIndexChanged.connect(self._on_gen_mode_changed)
        mode_row.addWidget(mode_lbl)
        mode_row.addWidget(self.mode_combo)
        gen_layout.addLayout(mode_row)

        self.gen_options_stack = QStackedWidget()
        pwd_options = QWidget()
        pwd_options_layout = QVBoxLayout(pwd_options)
        pwd_options_layout.setContentsMargins(0, 0, 0, 0)
        pwd_options_layout.setSpacing(10)

        slider_row = QHBoxLayout()
        slider_lbl = QLabel("Length")
        slider_lbl.setProperty("class", "metadata")
        self.slider_val_lbl = QLabel("20")
        self.slider_val_lbl.setStyleSheet(f"font-size: 13px; color: {ThemeManager.colors()['text_primary']}; font-weight: 500;")
        self.length_slider = QSlider(Qt.Orientation.Horizontal)
        self.length_slider.setRange(8, 64)
        self.length_slider.setValue(20)
        self.length_slider.valueChanged.connect(lambda v: self.slider_val_lbl.setText(str(v)))
        slider_row.addWidget(slider_lbl)
        slider_row.addWidget(self.length_slider)
        slider_row.addWidget(self.slider_val_lbl)
        pwd_options_layout.addLayout(slider_row)

        chk_row = QHBoxLayout()
        self.chk_upper = QCheckBox("Uppercase")
        self.chk_upper.setChecked(True)
        self.chk_lower = QCheckBox("Lowercase")
        self.chk_lower.setChecked(True)
        self.chk_digits = QCheckBox("Numbers")
        self.chk_digits.setChecked(True)
        self.chk_symbols = QCheckBox("Symbols")
        self.chk_symbols.setChecked(True)
        chk_row.addWidget(self.chk_upper)
        chk_row.addWidget(self.chk_lower)
        chk_row.addWidget(self.chk_digits)
        chk_row.addWidget(self.chk_symbols)
        pwd_options_layout.addLayout(chk_row)

        self.gen_options_stack.addWidget(pwd_options)

        phrase_options = QWidget()
        phrase_layout = QVBoxLayout(phrase_options)
        phrase_layout.setContentsMargins(0, 0, 0, 0)
        phrase_layout.setSpacing(10)

        word_row = QHBoxLayout()
        word_lbl = QLabel("Words")
        word_lbl.setProperty("class", "metadata")
        self.word_count_lbl = QLabel("5")
        self.word_count_lbl.setStyleSheet(f"font-size: 13px; color: {ThemeManager.colors()['text_primary']}; font-weight: 500;")
        self.word_count_slider = QSlider(Qt.Orientation.Horizontal)
        self.word_count_slider.setRange(3, 8)
        self.word_count_slider.setValue(5)
        self.word_count_slider.valueChanged.connect(lambda v: self.word_count_lbl.setText(str(v)))
        word_row.addWidget(word_lbl)
        word_row.addWidget(self.word_count_slider)
        word_row.addWidget(self.word_count_lbl)
        phrase_layout.addLayout(word_row)

        sep_row = QHBoxLayout()
        sep_lbl = QLabel("Separator")
        sep_lbl.setProperty("class", "metadata")
        self.sep_combo = QComboBox()
        self.sep_combo.addItems(["- (hyphen)", "_ (underscore)", ". (dot)", "  (space)"])
        sep_row.addWidget(sep_lbl)
        sep_row.addWidget(self.sep_combo)
        phrase_layout.addLayout(sep_row)

        self.chk_capitalize = QCheckBox("Capitalize each word")
        self.chk_capitalize.setChecked(False)
        phrase_layout.addWidget(self.chk_capitalize)

        self.gen_options_stack.addWidget(phrase_options)
        gen_layout.addWidget(self.gen_options_stack)

        btn_do_gen = QPushButton("Generate")
        btn_do_gen.setProperty("class", "primary")
        btn_do_gen.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_do_gen.clicked.connect(self._generate_password)
        gen_layout.addWidget(btn_do_gen)

        self.gen_frame.hide()
        login_layout.addWidget(self.gen_frame)

        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setProperty("strength", "weak")
        self.strength_bar.setFixedHeight(6)
        self.strength_bar.hide()
        login_layout.addWidget(self.strength_bar)

        self.strength_label = QLabel("")
        self.strength_label.setProperty("class", "metadata")
        login_layout.addWidget(self.strength_label)

        self.breach_label = QLabel("")
        self.breach_label.setProperty("class", "metadata")
        self.breach_label.hide()
        login_layout.addWidget(self.breach_label)

        url_lbl = QLabel("Website")
        url_lbl.setProperty("class", "metadata")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://google.com")
        login_layout.addWidget(url_lbl)
        login_layout.addWidget(self.url_input)

        self.field_stack.addWidget(self.page_login)

        # ==========================================
        # PAGE 1: CARD
        # ==========================================
        self.page_card = QWidget()
        card_layout = QVBoxLayout(self.page_card)
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(14)

        card_name_lbl = QLabel("Cardholder Name")
        card_name_lbl.setProperty("class", "metadata")
        self.card_name_input = QLineEdit()
        card_layout.addWidget(card_name_lbl)
        card_layout.addWidget(self.card_name_input)

        card_num_lbl = QLabel("Card Number")
        card_num_lbl.setProperty("class", "metadata")
        self.card_num_input = QLineEdit()
        card_layout.addWidget(card_num_lbl)
        card_layout.addWidget(self.card_num_input)

        row_card = QHBoxLayout()
        
        col_exp = QVBoxLayout()
        exp_lbl = QLabel("Expiration (MM/YY)")
        exp_lbl.setProperty("class", "metadata")
        self.card_exp_input = QLineEdit()
        col_exp.addWidget(exp_lbl)
        col_exp.addWidget(self.card_exp_input)
        row_card.addLayout(col_exp)

        col_cvv = QVBoxLayout()
        cvv_lbl = QLabel("CVV")
        cvv_lbl.setProperty("class", "metadata")
        self.card_cvv_input = QLineEdit()
        self.card_cvv_input.setEchoMode(QLineEdit.EchoMode.Password)
        col_cvv.addWidget(cvv_lbl)
        col_cvv.addWidget(self.card_cvv_input)
        row_card.addLayout(col_cvv)

        col_pin = QVBoxLayout()
        pin_lbl = QLabel("PIN")
        pin_lbl.setProperty("class", "metadata")
        self.card_pin_input = QLineEdit()
        self.card_pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        col_pin.addWidget(pin_lbl)
        col_pin.addWidget(self.card_pin_input)
        row_card.addLayout(col_pin)

        card_layout.addLayout(row_card)
        card_layout.addStretch()
        self.field_stack.addWidget(self.page_card)

        # ==========================================
        # PAGE 2: SECURE NOTE
        # ==========================================
        self.page_note = QWidget()
        note_layout = QVBoxLayout(self.page_note)
        note_layout.setContentsMargins(0, 0, 0, 0)
        note_layout.setSpacing(14)
        
        # Secure Note has no extra fields, uses common Notes field.
        note_layout.addStretch()
        self.field_stack.addWidget(self.page_note)

        # ==========================================
        # PAGE 3: IDENTITY
        # ==========================================
        self.page_identity = QWidget()
        id_layout = QVBoxLayout(self.page_identity)
        id_layout.setContentsMargins(0, 0, 0, 0)
        id_layout.setSpacing(14)

        id_name_lbl = QLabel("Full Name")
        id_name_lbl.setProperty("class", "metadata")
        self.id_name_input = QLineEdit()
        id_layout.addWidget(id_name_lbl)
        id_layout.addWidget(self.id_name_input)

        id_email_lbl = QLabel("Email")
        id_email_lbl.setProperty("class", "metadata")
        self.id_email_input = QLineEdit()
        id_layout.addWidget(id_email_lbl)
        id_layout.addWidget(self.id_email_input)

        id_phone_lbl = QLabel("Phone")
        id_phone_lbl.setProperty("class", "metadata")
        self.id_phone_input = QLineEdit()
        id_layout.addWidget(id_phone_lbl)
        id_layout.addWidget(self.id_phone_input)

        id_addr_lbl = QLabel("Address")
        id_addr_lbl.setProperty("class", "metadata")
        self.id_addr_input = QTextEdit()
        self.id_addr_input.setMaximumHeight(50)
        id_layout.addWidget(id_addr_lbl)
        id_layout.addWidget(self.id_addr_input)

        id_ssn_lbl = QLabel("SSN / ID Number")
        id_ssn_lbl.setProperty("class", "metadata")
        self.id_ssn_input = QLineEdit()
        id_layout.addWidget(id_ssn_lbl)
        id_layout.addWidget(self.id_ssn_input)
        
        id_layout.addStretch()
        self.field_stack.addWidget(self.page_identity)

        # ==========================================
        # NOTES (Common to all)
        # ==========================================
        self.notes_lbl = QLabel("Notes")
        self.notes_lbl.setProperty("class", "metadata")
        self.notes_input = QTextEdit()
        self.notes_input.setPlaceholderText("")
        self.notes_input.setMaximumHeight(72)
        layout.addWidget(self.notes_lbl)
        layout.addWidget(self.notes_input)

        layout.addSpacing(8)

        # Action Buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.setProperty("class", "outline")
        btn_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)

        btn_row.addSpacing(8)
        btn_save = QPushButton("Save")
        btn_save.setProperty("class", "primary")
        btn_save.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_save.clicked.connect(self._handle_save)
        btn_row.addWidget(btn_save)

        layout.addLayout(btn_row)
        
        self._on_category_changed(self.cat_combo.currentIndex())

    def _on_category_changed(self, idx: int):
        self.field_stack.setCurrentIndex(idx)
        titles = ["Add Login", "Add Card", "Add Secure Note", "Add Identity"]
        if self.edit_entry_id:
            titles = ["Edit Login", "Edit Card", "Edit Secure Note", "Edit Identity"]
        if 0 <= idx < len(titles):
            self.header.setText(titles[idx])
        
        # Adjust Title Label
        if idx == 0:
            self.title_lbl.setText("Name")
        elif idx == 1:
            self.title_lbl.setText("Card Name")
        elif idx == 2:
            self.title_lbl.setText("Note Title")
        elif idx == 3:
            self.title_lbl.setText("Identity Name")

        # Adjust Notes size
        if idx == 2:
            self.notes_input.setMaximumHeight(200)
            self.notes_input.setMinimumHeight(150)
        else:
            self.notes_input.setMaximumHeight(72)
            self.notes_input.setMinimumHeight(0)

    def _update_strength(self, pwd: str):
        if not pwd:
            self.strength_label.setText("")
            self.strength_bar.hide()
            self.breach_label.hide()
            return

        try:
            result = calculate_password_strength(pwd)
            label = result['label']
            score = result['score']

            # Map label → strength property for themed QProgressBar colors
            strength_map = {
                'Weak': 'weak',
                'Fair': 'fair',
                'Good': 'good',
                'Strong': 'strong',
                'Very Strong': 'strong',
            }
            strength_key = strength_map.get(label, 'weak')

            colors = {
                'Weak': '#E5484D',
                'Fair': '#E5A63E',
                'Good': '#2D7FF9',
                'Strong': '#30A46C',
                'Very Strong': '#30A46C'
            }
            color = colors.get(label, '#5F6570')

            # Update progress bar
            self.strength_bar.show()
            self.strength_bar.setValue(score)
            self.strength_bar.setProperty("strength", strength_key)
            self.strength_bar.style().unpolish(self.strength_bar)
            self.strength_bar.style().polish(self.strength_bar)

            # Update text label
            self.strength_label.setText(
                f"<span style='color: {color}; font-weight: 500;'>{label}</span>"
                f"<span style='color: #5F6570;'>  ·  {result['entropy']} bits</span>"
            )
        except Exception:
            # Non-critical — don't crash on strength calculation
            pass

    # ── Breach Detection ────────────────────────────────────────────────

    def _schedule_breach_check(self, pwd: str):
        """Debounce breach check — wait 800ms after last keystroke."""
        if not pwd:
            self.breach_label.hide()
            self._breach_debounce.stop()
            try:
                self._breach_checker.cancel()
            except Exception:
                pass
            return
        self._breach_debounce.start()

    def _trigger_breach_check(self):
        """Fire the actual breach check after debounce expires."""
        try:
            pwd = self.pwd_input.text()
            if not pwd:
                return
            self.breach_label.show()
            self.breach_label.setText(
                "<span style='color: #5F6570;'>Checking breach databases…</span>"
            )
            self._breach_checker.check(
                pwd,
                on_result=self._on_breach_result,
                on_error=self._on_breach_error,
            )
        except Exception:
            self.breach_label.hide()

    def _on_breach_result(self, is_breached: bool, count: int):
        """Handle breach check result."""
        try:
            if is_breached:
                self.breach_label.setText(
                    f"<span style='color: #E5484D; font-weight: 500;'>"
                    f"⚠ Found in {count:,} data breaches</span>"
                    f"<span style='color: #5F6570;'> — consider a different password</span>"
                )
            else:
                self.breach_label.setText(
                    "<span style='color: #30A46C; font-weight: 500;'>"
                    "✓ Not found in known breaches</span>"
                )
        except Exception:
            pass

    def _on_breach_error(self, error_msg: str):
        """Handle breach check network error — non-blocking."""
        try:
            self.breach_label.setText(
                "<span style='color: #5F6570;'>Could not check breaches (offline?)</span>"
            )
        except Exception:
            pass

    def _toggle_password_visibility(self):
        if self.pwd_input.echoMode() == QLineEdit.EchoMode.Password:
            self.pwd_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_toggle_pwd.setText("🙈")
        else:
            self.pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_toggle_pwd.setText("👁")

    def _toggle_generator(self):
        if self.gen_frame.isVisible():
            self.gen_frame.hide()
        else:
            self.gen_frame.show()

    def _on_gen_mode_changed(self, idx: int):
        self.gen_options_stack.setCurrentIndex(idx)

    def _generate_password(self):
        try:
            mode = self.mode_combo.currentIndex()
            if mode == 0:  # Random Password
                length = self.length_slider.value()
                upper = self.chk_upper.isChecked()
                lower = self.chk_lower.isChecked()
                digits = self.chk_digits.isChecked()
                symbols = self.chk_symbols.isChecked()

                if not any([upper, lower, digits, symbols]):
                    self.chk_lower.setChecked(True)
                    lower = True

                pwd = generate_random_password(
                    length=length,
                    upper=upper,
                    lower=lower,
                    digits=digits,
                    symbols=symbols,
                )
            else:  # Passphrase
                count = self.word_count_slider.value()
                sep_map = {0: "-", 1: "_", 2: ".", 3: " "}
                sep = sep_map.get(self.sep_combo.currentIndex(), "-")
                cap = self.chk_capitalize.isChecked()

                pwd = generate_passphrase(
                    word_count=count,
                    separator=sep,
                    capitalize=cap,
                )

            self.pwd_input.setText(pwd)
            self.pwd_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_toggle_pwd.setText("🙈")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Password generation failed: {e}")

    def _handle_save(self):
        """Save the vault entry with comprehensive error handling."""
        title = self.title_input.text().strip()
        notes_text = self.notes_input.toPlainText().strip()

        cat_map = {0: 'login', 1: 'card', 2: 'note', 3: 'identity'}
        idx = self.cat_combo.currentIndex()
        category = cat_map.get(idx, 'login')

        if not title:
            QMessageBox.warning(self, "Required", "Name/Title is required.")
            return

        username = ""
        password = ""
        url = ""
        extra_data = {}

        if category == 'login':
            username = self.user_input.text().strip()
            password = self.pwd_input.text()
            url = self.url_input.text().strip()
            if not password:
                QMessageBox.warning(self, "Required", "Password is required for Login.")
                return
        elif category == 'card':
            username = self.card_name_input.text().strip()
            password = self.card_num_input.text().strip()
            extra_data = {
                "exp": self.card_exp_input.text().strip(),
                "cvv": self.card_cvv_input.text().strip(),
                "pin": self.card_pin_input.text().strip()
            }
        elif category == 'note':
            # Secure notes don't require username/password
            password = ""
            username = ""
        elif category == 'identity':
            username = self.id_name_input.text().strip()
            password = self.id_ssn_input.text().strip()
            extra_data = {
                "email": self.id_email_input.text().strip(),
                "phone": self.id_phone_input.text().strip(),
                "address": self.id_addr_input.toPlainText().strip()
            }
        
        extra_data["notes"] = notes_text
        notes_json = json.dumps(extra_data)

        # ── Encrypt all fields with error handling ──
        try:
            enc_title, n_title = encrypt_data(title, self.vault_key)
        except Exception as e:
            QMessageBox.critical(
                self, "Encryption Error",
                f"Failed to encrypt title: {e}\n\n"
                "The vault key may be invalid. Try locking and unlocking the vault."
            )
            return

        try:
            enc_user, n_user = encrypt_data(username, self.vault_key) if username else (None, None)
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", f"Failed to encrypt username: {e}")
            return

        try:
            if password:
                enc_pass, n_pass = encrypt_data(password, self.vault_key)
            else:
                # For Secure Notes and empty passwords, store an empty encrypted value
                enc_pass, n_pass = encrypt_data("", self.vault_key)
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", f"Failed to encrypt password: {e}")
            return

        try:
            enc_url, n_url = encrypt_data(url, self.vault_key) if url else (None, None)
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", f"Failed to encrypt URL: {e}")
            return

        try:
            enc_notes, n_notes = encrypt_data(notes_json, self.vault_key)
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", f"Failed to encrypt notes: {e}")
            return

        # ── Database operation with error handling ──
        try:
            with Session() as session:
                if self.edit_entry_id:
                    entry = session.query(VaultEntry).filter_by(
                        id=self.edit_entry_id, user_id=self.user_id
                    ).first()
                    if entry:
                        entry.encrypted_title = enc_title
                        entry.nonce_title = n_title
                        entry.encrypted_username = enc_user
                        entry.nonce_username = n_user
                        entry.encrypted_password = enc_pass
                        entry.nonce_password = n_pass
                        entry.encrypted_url = enc_url
                        entry.nonce_url = n_url
                        entry.encrypted_notes = enc_notes
                        entry.nonce_notes = n_notes
                        entry.category = category
                        session.commit()
                    else:
                        QMessageBox.warning(
                            self, "Not Found",
                            "The entry you're trying to edit no longer exists."
                        )
                        return
                else:
                    entry = VaultEntry(
                        user_id=self.user_id,
                        encrypted_title=enc_title, nonce_title=n_title,
                        encrypted_username=enc_user, nonce_username=n_user,
                        encrypted_password=enc_pass, nonce_password=n_pass,
                        encrypted_url=enc_url, nonce_url=n_url,
                        encrypted_notes=enc_notes, nonce_notes=n_notes,
                        category=category,
                    )
                    session.add(entry)
                    session.commit()
        except Exception as e:
            QMessageBox.critical(
                self, "Save Error",
                f"Failed to save credential to database:\n{e}"
            )
            traceback.print_exc()
            return

        self.entry_saved.emit()
        self.accept()


    def _load_entry_data(self):
        """Load existing entry data for editing with full error handling."""
        try:
            with Session() as session:
                entry = session.query(VaultEntry).filter_by(
                    id=self.edit_entry_id, user_id=self.user_id
                ).first()
                if not entry:
                    return

                cat_map_rev = {'login': 0, 'card': 1, 'note': 2, 'identity': 3}
                idx = cat_map_rev.get(entry.category or 'login', 0)
                self.cat_combo.setCurrentIndex(idx)

                try:
                    title = decrypt_data(entry.encrypted_title, entry.nonce_title, self.vault_key)
                except Exception:
                    title = ""
                self.title_input.setText(title)

                username = ""
                if entry.encrypted_username and entry.nonce_username:
                    try:
                        username = decrypt_data(entry.encrypted_username, entry.nonce_username, self.vault_key)
                    except Exception:
                        username = ""
                
                password = ""
                if entry.encrypted_password and entry.nonce_password:
                    try:
                        password = decrypt_data(entry.encrypted_password, entry.nonce_password, self.vault_key)
                    except Exception:
                        password = ""
                    
                url = ""
                if entry.encrypted_url and entry.nonce_url:
                    try:
                        url = decrypt_data(entry.encrypted_url, entry.nonce_url, self.vault_key)
                    except Exception:
                        url = ""
                    
                notes_json = ""
                if entry.encrypted_notes and entry.nonce_notes:
                    try:
                        notes_json = decrypt_data(entry.encrypted_notes, entry.nonce_notes, self.vault_key)
                    except Exception:
                        notes_json = ""
                    
                extra_data = {}
                if notes_json:
                    try:
                        extra_data = json.loads(notes_json)
                    except Exception:
                        extra_data = {"notes": notes_json}

                self.notes_input.setText(extra_data.get("notes", ""))

                category = entry.category or 'login'
                if category == 'login':
                    self.user_input.setText(username)
                    self.pwd_input.setText(password)
                    self.url_input.setText(url)
                elif category == 'card':
                    self.card_name_input.setText(username)
                    self.card_num_input.setText(password)
                    self.card_exp_input.setText(extra_data.get("exp", ""))
                    self.card_cvv_input.setText(extra_data.get("cvv", ""))
                    self.card_pin_input.setText(extra_data.get("pin", ""))
                elif category == 'identity':
                    self.id_name_input.setText(username)
                    self.id_ssn_input.setText(password)
                    self.id_email_input.setText(extra_data.get("email", ""))
                    self.id_phone_input.setText(extra_data.get("phone", ""))
                    self.id_addr_input.setText(extra_data.get("address", ""))
        except Exception as e:
            QMessageBox.warning(
                self, "Load Error",
                f"Failed to load entry data: {e}"
            )
            traceback.print_exc()
