"""Login and Registration Window for Cipher."""

import time
import traceback
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QStackedWidget, QMessageBox,
    QGraphicsOpacityEffect
)
from PyQt6.QtCore import Qt, pyqtSignal, QPropertyAnimation, QEasingCurve, QTimer
from models import Session
from models.user import User
from services.crypto import (
    hash_password, verify_password, generate_salt,
    derive_kek, generate_vault_key, wrap_vault_key, unwrap_vault_key
)


class LoginWindow(QWidget):
    """Window handling both unlocking an existing vault and creating a new one."""

    # Signal emitted upon successful authentication: (user_id, username, vault_key_bytes)
    authenticated = pyqtSignal(int, str, bytes)

    def __init__(self):
        super().__init__()
        self.login_attempts: dict[str, dict] = {}
        self._init_ui()
        self._fade_in()

    def _init_ui(self):
        self.setWindowTitle("Cipher")
        self.setFixedSize(420, 540)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Container
        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(40, 40, 40, 40)
        container_layout.setSpacing(0)
        container_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Brand
        brand_label = QLabel("◈  Cipher")
        brand_label.setProperty("class", "title")
        brand_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(brand_label)
        container_layout.addSpacing(40)

        # Flash / notification banner
        self.banner = QLabel()
        self.banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.banner.setWordWrap(True)
        self.banner.hide()
        container_layout.addWidget(self.banner)
        container_layout.addSpacing(8)

        # Stacked pages for Login / Register
        self.stack = QStackedWidget()
        self.stack.addWidget(self._create_login_page())
        self.stack.addWidget(self._create_register_page())
        container_layout.addWidget(self.stack)

        # Opacity effect for fade-in
        self.opacity_effect = QGraphicsOpacityEffect(container)
        self.opacity_effect.setOpacity(0.0)
        container.setGraphicsEffect(self.opacity_effect)

        main_layout.addWidget(container)

    def _fade_in(self):
        """Subtle fade-in on load."""
        self.fade_anim = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_anim.setDuration(250)
        self.fade_anim.setStartValue(0.0)
        self.fade_anim.setEndValue(1.0)
        self.fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        # Delay slightly to let the window render first
        QTimer.singleShot(50, self.fade_anim.start)

    def _create_login_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        header = QLabel("Unlock Vault")
        header.setProperty("class", "section")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        layout.addSpacing(8)

        # Username
        user_lbl = QLabel("Username")
        user_lbl.setProperty("class", "metadata")
        self.login_user_input = QLineEdit()
        self.login_user_input.setPlaceholderText("Enter your username")
        layout.addWidget(user_lbl)
        layout.addWidget(self.login_user_input)

        # Master Password
        pwd_lbl = QLabel("Master Password")
        pwd_lbl.setProperty("class", "metadata")
        self.login_pwd_input = QLineEdit()
        self.login_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_pwd_input.setPlaceholderText("Enter master password")
        self.login_pwd_input.returnPressed.connect(self._handle_login)
        layout.addWidget(pwd_lbl)
        layout.addWidget(self.login_pwd_input)

        layout.addSpacing(4)

        # Unlock Button
        btn_unlock = QPushButton("Unlock")
        btn_unlock.setProperty("class", "primary")
        btn_unlock.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_unlock.clicked.connect(self._handle_login)
        layout.addWidget(btn_unlock)

        layout.addSpacing(12)

        # Switch to Register
        switch_layout = QHBoxLayout()
        switch_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        switch_text = QLabel("Don't have a vault?")
        switch_text.setProperty("class", "muted")
        btn_switch = QPushButton("Create Vault")
        btn_switch.setProperty("class", "link")
        btn_switch.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_switch.clicked.connect(lambda: self._switch_page(1))
        switch_layout.addWidget(switch_text)
        switch_layout.addWidget(btn_switch)
        layout.addLayout(switch_layout)

        return page

    def _create_register_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        header = QLabel("Create New Vault")
        header.setProperty("class", "section")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        layout.addSpacing(8)

        # Username
        user_lbl = QLabel("Username")
        user_lbl.setProperty("class", "metadata")
        self.reg_user_input = QLineEdit()
        self.reg_user_input.setPlaceholderText("Choose a username")
        layout.addWidget(user_lbl)
        layout.addWidget(self.reg_user_input)

        # Master Password
        pwd_lbl = QLabel("Master Password (min. 12 chars)")
        pwd_lbl.setProperty("class", "metadata")
        self.reg_pwd_input = QLineEdit()
        self.reg_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_pwd_input.setPlaceholderText("Choose a strong master password")
        self.reg_pwd_input.textChanged.connect(self._update_reg_strength)
        layout.addWidget(pwd_lbl)
        layout.addWidget(self.reg_pwd_input)

        # Strength indicator
        from PyQt6.QtWidgets import QProgressBar
        self.reg_strength_bar = QProgressBar()
        self.reg_strength_bar.setRange(0, 100)
        self.reg_strength_bar.setValue(0)
        self.reg_strength_bar.setTextVisible(False)
        self.reg_strength_bar.setProperty("strength", "weak")
        self.reg_strength_bar.setFixedHeight(4)
        self.reg_strength_bar.hide()
        layout.addWidget(self.reg_strength_bar)

        self.reg_strength_label = QLabel("")
        self.reg_strength_label.setProperty("class", "metadata")
        layout.addWidget(self.reg_strength_label)

        # Confirm Password
        confirm_lbl = QLabel("Confirm Master Password")
        confirm_lbl.setProperty("class", "metadata")
        self.reg_confirm_input = QLineEdit()
        self.reg_confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_confirm_input.setPlaceholderText("Re-enter master password")
        layout.addWidget(confirm_lbl)
        layout.addWidget(self.reg_confirm_input)

        from gui.theme import ThemeManager
        warning_lbl = QLabel("Master password cannot be recovered if lost.")
        warning_lbl.setStyleSheet(f"color: {ThemeManager.colors()['warning']}; font-size: 12px;")
        warning_lbl.setWordWrap(True)
        layout.addWidget(warning_lbl)

        layout.addSpacing(4)

        # Register Button
        btn_register = QPushButton("Initialize Vault")
        btn_register.setProperty("class", "primary")
        btn_register.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_register.clicked.connect(self._handle_register)
        layout.addWidget(btn_register)

        layout.addSpacing(12)

        # Switch to Login
        switch_layout = QHBoxLayout()
        switch_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        switch_text = QLabel("Already have a vault?")
        switch_text.setProperty("class", "muted")
        btn_switch = QPushButton("Unlock")
        btn_switch.setProperty("class", "link")
        btn_switch.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_switch.clicked.connect(lambda: self._switch_page(0))
        switch_layout.addWidget(switch_text)
        switch_layout.addWidget(btn_switch)
        layout.addLayout(switch_layout)

        return page

    def _update_reg_strength(self, pwd: str):
        """Update the registration password strength indicator."""
        if not pwd:
            self.reg_strength_bar.hide()
            self.reg_strength_label.setText("")
            return

        try:
            from services.password_generator import calculate_password_strength
            result = calculate_password_strength(pwd)
            label = result['label']
            score = result['score']

            strength_map = {
                'Weak': 'weak', 'Fair': 'fair', 'Good': 'good',
                'Strong': 'strong', 'Very Strong': 'strong',
            }
            colors = {
                'Weak': '#E5484D', 'Fair': '#E5A63E', 'Good': '#2D7FF9',
                'Strong': '#30A46C', 'Very Strong': '#30A46C',
            }
            color = colors.get(label, '#5F6570')

            self.reg_strength_bar.show()
            self.reg_strength_bar.setValue(score)
            self.reg_strength_bar.setProperty("strength", strength_map.get(label, 'weak'))
            self.reg_strength_bar.style().unpolish(self.reg_strength_bar)
            self.reg_strength_bar.style().polish(self.reg_strength_bar)

            self.reg_strength_label.setText(
                f"<span style='color: {color}; font-weight: 500;'>{label}</span>"
                f"<span style='color: #5F6570;'>  ·  {result['entropy']} bits</span>"
            )
        except Exception:
            # Non-critical — don't crash on strength calculation
            pass

    def _switch_page(self, index: int):
        self.banner.hide()
        self.stack.setCurrentIndex(index)

    def show_message(self, text: str, category: str = "info"):
        self.banner.setText(text)
        self.banner.setProperty("class", f"flash-{category}")
        self.banner.style().unpolish(self.banner)
        self.banner.style().polish(self.banner)
        self.banner.show()

    def _handle_login(self):
        username = self.login_user_input.text().strip()
        password = self.login_pwd_input.text()

        if not username or not password:
            self.show_message("Please enter username and master password.", "danger")
            return

        # Rate limiting check
        current_time = time.time()
        attempt_data = self.login_attempts.get(username, {'count': 0, 'lockout_until': 0})

        if current_time < attempt_data['lockout_until']:
            wait_time = int(attempt_data['lockout_until'] - current_time)
            self.show_message(f"Account temporarily locked. Try again in {wait_time}s.", "danger")
            return

        try:
            with Session() as session:
                user = session.query(User).filter_by(username=username).first()

                if user and verify_password(user.password_hash, password):
                    # Reset rate limiter
                    self.login_attempts.pop(username, None)

                    # Derive KEK and unwrap vault key
                    try:
                        kek = derive_kek(password, user.kdf_salt)
                        vault_key = unwrap_vault_key(
                            user.encrypted_vault_key,
                            user.vault_key_nonce,
                            kek
                        )
                    except Exception:
                        self.show_message("Failed to unlock vault cryptographic key.", "danger")
                        return

                    # Clear inputs from memory
                    self.login_pwd_input.clear()
                    self.login_user_input.clear()

                    # Emit success
                    self.authenticated.emit(user.id, user.username, vault_key)
                else:
                    # Increment failed attempts
                    attempt_data['count'] += 1
                    if attempt_data['count'] >= 5:
                        backoff = (2 ** (attempt_data['count'] - 5)) * 60
                        attempt_data['lockout_until'] = current_time + backoff
                        self.show_message(f"Too many failed attempts. Locked for {int(backoff)}s.", "danger")
                    else:
                        self.show_message("Invalid username or master password.", "danger")
                    self.login_attempts[username] = attempt_data
        except Exception as e:
            self.show_message(f"Login error: {e}", "danger")
            traceback.print_exc()

    def _handle_register(self):
        username = self.reg_user_input.text().strip()
        password = self.reg_pwd_input.text()
        confirm = self.reg_confirm_input.text()

        if not username or not password:
            self.show_message("Username and password are required.", "danger")
            return

        if len(username) > 150:
            self.show_message("Username must be 150 characters or fewer.", "danger")
            return

        if len(password) < 12:
            self.show_message("Master password must be at least 12 characters.", "danger")
            return

        if password != confirm:
            self.show_message("Passwords do not match.", "danger")
            return

        try:
            with Session() as session:
                existing = session.query(User).filter_by(username=username).first()
                if existing:
                    self.show_message("Username already exists.", "danger")
                    return

                # Cryptographic setup — each step can fail
                try:
                    password_hash = hash_password(password)
                except Exception as e:
                    self.show_message(f"Password hashing failed: {e}", "danger")
                    return

                auth_salt = generate_salt()
                kdf_salt = generate_salt()

                try:
                    kek = derive_kek(password, kdf_salt)
                except Exception as e:
                    self.show_message(f"Key derivation failed: {e}", "danger")
                    return

                vault_key = generate_vault_key()

                try:
                    encrypted_vault_key, vault_key_nonce = wrap_vault_key(vault_key, kek)
                except Exception as e:
                    self.show_message(f"Key wrapping failed: {e}", "danger")
                    return

                new_user = User(
                    username=username,
                    password_hash=password_hash,
                    salt=auth_salt,
                    kdf_salt=kdf_salt,
                    encrypted_vault_key=encrypted_vault_key,
                    vault_key_nonce=vault_key_nonce,
                )
                session.add(new_user)

                try:
                    session.commit()
                except Exception as e:
                    session.rollback()
                    self.show_message(f"Failed to save user: {e}", "danger")
                    return

        except Exception as e:
            self.show_message(f"Registration failed: {e}", "danger")
            traceback.print_exc()
            return

        self.reg_pwd_input.clear()
        self.reg_confirm_input.clear()
        self.reg_user_input.clear()
        self._switch_page(0)
        self.login_user_input.setText(username)
        self.login_pwd_input.setFocus()
        self.show_message("Vault created successfully. Please enter your master password to unlock.", "success")
