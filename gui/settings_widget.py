"""Settings widget for Cipher.

Handles master password changes (with proper vault key re-wrapping),
auto-lock preferences, and vault export/import operations.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QScrollArea, QMessageBox, QFileDialog,
    QColorDialog, QGridLayout
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from models import Session
from models.user import User
from services.crypto import (
    verify_password, hash_password, generate_salt,
    derive_kek, unwrap_vault_key, wrap_vault_key,
)
from config import Config


from gui.theme import ThemeManager


class SettingsWidget(QWidget):
    """Settings screen for changing master password and preferences."""

    # Emitted when the auto-lock timeout changes so MainWindow can update its timer
    lock_timeout_changed = pyqtSignal(int)  # new timeout in seconds

    def __init__(self, user_id: int, vault_key: bytes, parent=None):
        super().__init__(parent)
        self.user_id = user_id
        self.vault_key = vault_key
        self._theme_buttons: dict[str, QPushButton] = {}
        self._color_swatches: dict[str, QPushButton] = {}
        self._init_ui()

    def _init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(0)

        # Title
        title_lbl = QLabel("Settings")
        title_lbl.setProperty("class", "section")
        layout.addWidget(title_lbl)
        layout.addSpacing(28)

        # ── Appearance Section ────────────────────────────────────────
        app_lbl = QLabel("APPEARANCE")
        app_lbl.setProperty("class", "nav-section")
        layout.addWidget(app_lbl)
        layout.addSpacing(16)

        theme_desc = QLabel("Choose your visual theme")
        theme_desc.setProperty("class", "muted")
        layout.addWidget(theme_desc)
        layout.addSpacing(12)

        theme_row = QHBoxLayout()
        theme_row.setSpacing(10)

        current_theme = ThemeManager.get_current_theme()

        for theme_name, label, icon in [
            ("dark", "Dark", "🌙"),
            ("light", "Light", "☀️"),
            ("custom", "Custom", "🎨"),
        ]:
            btn = QPushButton(f"{icon}  {label}")
            btn.setProperty("class", "theme-option")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setFixedHeight(42)
            btn.setMinimumWidth(100)

            if theme_name == current_theme:
                btn.setChecked(True)

            btn.clicked.connect(
                lambda checked, name=theme_name: self._on_theme_selected(name)
            )

            theme_row.addWidget(btn)
            self._theme_buttons[theme_name] = btn

        theme_row.addStretch()
        layout.addLayout(theme_row)
        layout.addSpacing(16)

        # ── Custom Theme Editor (hidden by default) ───────────────────
        self.custom_editor = QFrame()
        self.custom_editor.setProperty("class", "card")
        editor_layout = QVBoxLayout(self.custom_editor)
        editor_layout.setContentsMargins(20, 18, 20, 18)
        editor_layout.setSpacing(0)

        editor_title = QLabel("Customize Colors")
        editor_title.setProperty("class", "subtitle")
        editor_layout.addWidget(editor_title)
        editor_layout.addSpacing(4)

        editor_desc = QLabel("Click a swatch to pick a color. Changes apply live.")
        editor_desc.setProperty("class", "muted")
        editor_layout.addWidget(editor_desc)
        editor_layout.addSpacing(16)

        # Color picker grid
        color_grid = QGridLayout()
        color_grid.setSpacing(12)
        color_grid.setColumnMinimumWidth(0, 130)
        color_grid.setColumnMinimumWidth(1, 44)
        color_grid.setColumnStretch(2, 1)

        custom_colors = ThemeManager.get_custom_colors()

        # Grouped editable tokens: (token_key, label, hint) or None for section header
        editable_groups = [
            # ── Core Colors
            ('_header',         'CORE COLORS',    ''),
            ('bg',              'Background',     'Main app background'),
            ('surface',         'Surface',        'Cards, inputs, panels'),
            ('elevated',        'Elevated',       'Elevated surfaces, dropdowns'),
            ('text_primary',    'Text',           'Headings and body text'),
            ('text_secondary',  'Secondary Text', 'Subtitles, metadata'),
            ('text_muted',      'Muted Text',     'Hints, placeholders'),
            ('accent',          'Accent',         'Buttons, links, focus rings'),
            ('border',          'Border',         'Dividers, card edges'),
            ('border_subtle',   'Subtle Border',  'Faint separators'),

            # ── Gradients
            ('_header',         'GRADIENTS',      ''),
            ('grad_start',      'App Start',      'Window background gradient start'),
            ('grad_end',        'App End',        'Window background gradient end'),
            ('sidebar_grad_start', 'Sidebar Start', 'Sidebar gradient start'),
            ('sidebar_grad_end',   'Sidebar End',   'Sidebar gradient end'),
            ('card_grad_start', 'Card Start',     'Card background gradient start'),
            ('card_grad_end',   'Card End',       'Card background gradient end'),

            # ── Buttons & Accents
            ('_header',         'BUTTONS',        ''),
            ('primary_grad_start', 'Primary Start',  'Primary button gradient start'),
            ('primary_grad_end',   'Primary End',    'Primary button gradient end'),
            ('accent_hover',    'Accent Hover',   'Accent on hover'),
            ('accent_pressed',  'Accent Pressed', 'Accent when pressed'),

            # ── Semantic
            ('_header',         'STATUS COLORS',  ''),
            ('success',         'Success',        'Positive indicators'),
            ('warning',         'Warning',        'Warning indicators'),
            ('danger',          'Danger',         'Error, destructive actions'),
        ]

        grid_row = 0
        for token, label, hint in editable_groups:
            if token == '_header':
                # Section header spanning all columns
                if grid_row > 0:
                    # Add spacing before headers (except first)
                    spacer = QLabel("")
                    spacer.setFixedHeight(8)
                    color_grid.addWidget(spacer, grid_row, 0, 1, 3)
                    grid_row += 1
                header = QLabel(label)
                header.setProperty("class", "nav-section")
                color_grid.addWidget(header, grid_row, 0, 1, 3)
                grid_row += 1
                continue

            # Label
            token_lbl = QLabel(label)
            token_lbl.setToolTip(hint)
            color_grid.addWidget(token_lbl, grid_row, 0)

            # Color swatch button
            color_val = custom_colors.get(token, '#000000')
            swatch = QPushButton()
            swatch.setFixedSize(36, 28)
            swatch.setCursor(Qt.CursorShape.PointingHandCursor)
            swatch.setToolTip(f"{hint}\nCurrent: {color_val}")
            self._update_swatch_style(swatch, color_val)
            swatch.clicked.connect(
                lambda checked, t=token, s=swatch: self._pick_color(t, s)
            )
            color_grid.addWidget(swatch, grid_row, 1)
            self._color_swatches[token] = swatch

            # Hex value label
            hex_lbl = QLabel(color_val)
            hex_lbl.setProperty("class", "metadata")
            hex_lbl.setObjectName(f"hex_{token}")
            color_grid.addWidget(hex_lbl, grid_row, 2)
            
            grid_row += 1
        editor_layout.addLayout(color_grid)
        editor_layout.addSpacing(16)

        # Reset button
        btn_reset = QPushButton("Reset to Defaults")
        btn_reset.setProperty("class", "small-outline")
        btn_reset.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_reset.setMaximumWidth(150)
        btn_reset.clicked.connect(self._reset_custom_theme)
        editor_layout.addWidget(btn_reset)

        layout.addWidget(self.custom_editor)

        # Show/hide based on current theme
        self.custom_editor.setVisible(current_theme == 'custom')

        layout.addSpacing(24)

        # Separator
        layout.addWidget(self._separator())
        layout.addSpacing(24)

        # ── Security Section ──────────────────────────────────────────
        sec_lbl = QLabel("SECURITY")
        sec_lbl.setProperty("class", "nav-section")
        layout.addWidget(sec_lbl)
        layout.addSpacing(16)

        # Change Master Password
        cmp_lbl = QLabel("Change Master Password")
        cmp_lbl.setProperty("class", "metadata")
        layout.addWidget(cmp_lbl)
        layout.addSpacing(8)

        self.old_pwd = QLineEdit()
        self.old_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.old_pwd.setPlaceholderText("Current master password")
        self.old_pwd.setMaximumWidth(300)
        layout.addWidget(self.old_pwd)
        layout.addSpacing(8)

        self.new_pwd = QLineEdit()
        self.new_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pwd.setPlaceholderText("New master password (min 12 chars)")
        self.new_pwd.setMaximumWidth(300)
        layout.addWidget(self.new_pwd)
        layout.addSpacing(8)

        self.confirm_pwd = QLineEdit()
        self.confirm_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pwd.setPlaceholderText("Confirm new master password")
        self.confirm_pwd.setMaximumWidth(300)
        layout.addWidget(self.confirm_pwd)
        layout.addSpacing(12)

        btn_change_pwd = QPushButton("Update Password")
        btn_change_pwd.setProperty("class", "outline")
        btn_change_pwd.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_change_pwd.setMaximumWidth(160)
        btn_change_pwd.clicked.connect(self._handle_change_password)
        layout.addWidget(btn_change_pwd)
        layout.addSpacing(24)

        # Separator
        layout.addWidget(self._separator())
        layout.addSpacing(24)

        # ── Preferences Section ───────────────────────────────────────
        pref_lbl = QLabel("PREFERENCES")
        pref_lbl.setProperty("class", "nav-section")
        layout.addWidget(pref_lbl)
        layout.addSpacing(16)

        lock_lbl = QLabel("Auto-lock Timeout (seconds)")
        lock_lbl.setProperty("class", "metadata")
        layout.addWidget(lock_lbl)
        layout.addSpacing(8)

        self.lock_timeout = QLineEdit()
        self.lock_timeout.setText(str(Config.VAULT_LOCK_SECONDS))
        self.lock_timeout.setMaximumWidth(100)
        layout.addWidget(self.lock_timeout)
        layout.addSpacing(12)

        btn_save_pref = QPushButton("Save Preferences")
        btn_save_pref.setProperty("class", "outline")
        btn_save_pref.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_save_pref.setMaximumWidth(160)
        btn_save_pref.clicked.connect(self._handle_save_preferences)
        layout.addWidget(btn_save_pref)

        layout.addSpacing(24)

        # Separator
        layout.addWidget(self._separator())
        layout.addSpacing(24)

        # ── Data Section ──────────────────────────────────────────────
        data_lbl = QLabel("DATA")
        data_lbl.setProperty("class", "nav-section")
        layout.addWidget(data_lbl)
        layout.addSpacing(16)

        export_desc = QLabel("Export or import your vault data.")
        export_desc.setProperty("class", "muted")
        layout.addWidget(export_desc)
        layout.addSpacing(12)

        data_row = QHBoxLayout()
        data_row.setSpacing(8)

        btn_export = QPushButton("Export Vault")
        btn_export.setProperty("class", "outline")
        btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_export.setMaximumWidth(140)
        btn_export.clicked.connect(self._handle_export)
        data_row.addWidget(btn_export)

        btn_import = QPushButton("Import Vault")
        btn_import.setProperty("class", "outline")
        btn_import.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_import.setMaximumWidth(140)
        btn_import.clicked.connect(self._handle_import)
        data_row.addWidget(btn_import)

        data_row.addStretch()
        layout.addLayout(data_row)
        layout.addSpacing(24)

        # Status message label
        self.status_msg = QLabel("")
        self.status_msg.hide()
        layout.addWidget(self.status_msg)

        layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll)

    def _separator(self) -> QFrame:
        sep = QFrame()
        sep.setProperty("class", "separator")
        sep.setFixedHeight(1)
        return sep

    # ── Theme Selection ───────────────────────────────────────────────

    def _on_theme_selected(self, name: str):
        """Handle theme toggle button click — apply theme and persist."""
        # Update button checked states
        for key, btn in self._theme_buttons.items():
            btn.setChecked(key == name)

        # Show/hide custom editor
        self.custom_editor.setVisible(name == 'custom')

        # If switching to custom, refresh swatches from current overrides
        if name == 'custom':
            self._refresh_swatches()

        # Apply theme live
        ThemeManager.apply_theme(name)

        # Persist
        Config.THEME = name
        Config.save_settings()

    def _update_swatch_style(self, swatch: QPushButton, color: str):
        """Update a swatch button's background to show the color."""
        # For rgba() values, use a simpler display
        if color.startswith('rgba'):
            display = '#808080'
        else:
            display = color
        swatch.setStyleSheet(
            f"background-color: {display}; "
            f"border: 2px solid {ThemeManager.colors()['border_hover']}; "
            f"border-radius: 6px;"
        )

    def _pick_color(self, token: str, swatch: QPushButton):
        """Open QColorDialog for a custom theme token."""
        from PyQt6.QtGui import QColor

        current = ThemeManager.get_custom_colors().get(token, '#000000')
        if current.startswith('rgba'):
            initial = QColor(128, 128, 128)
        else:
            initial = QColor(current)

        color = QColorDialog.getColor(
            initial, self, f"Pick color for {token}"
        )

        if color.isValid():
            hex_val = color.name()  # e.g. '#2d7ff9'

            # Update swatch visual
            self._update_swatch_style(swatch, hex_val)
            swatch.setToolTip(f"Current: {hex_val}")

            # Update hex label
            hex_lbl = self.custom_editor.findChild(QLabel, f"hex_{token}")
            if hex_lbl:
                hex_lbl.setText(hex_val)

            # Apply to theme manager (live preview)
            ThemeManager.set_custom_color(token, hex_val)

            # Persist
            Config.CUSTOM_THEME_COLORS = ThemeManager.save_custom_colors()
            Config.save_settings()

    def _refresh_swatches(self):
        """Refresh all swatch colors from current ThemeManager state."""
        custom_colors = ThemeManager.get_custom_colors()
        for token, swatch in self._color_swatches.items():
            color_val = custom_colors.get(token, '#000000')
            self._update_swatch_style(swatch, color_val)
            swatch.setToolTip(f"Current: {color_val}")

            hex_lbl = self.custom_editor.findChild(QLabel, f"hex_{token}")
            if hex_lbl:
                hex_lbl.setText(color_val)

    def _reset_custom_theme(self):
        """Reset custom theme to dark defaults."""
        ThemeManager.reset_custom_theme()

        # Persist cleared overrides
        Config.CUSTOM_THEME_COLORS = {}
        Config.save_settings()

        # Refresh swatches
        self._refresh_swatches()

        self._show_message("Custom theme reset to defaults.")

    def _show_message(self, message: str, is_error: bool = False):
        self.status_msg.setText(message)
        if is_error:
            self.status_msg.setProperty("class", "flash-danger")
        else:
            self.status_msg.setProperty("class", "flash-success")

        # Force stylesheet update
        self.status_msg.style().unpolish(self.status_msg)
        self.status_msg.style().polish(self.status_msg)
        self.status_msg.show()

        QTimer.singleShot(5000, self.status_msg.hide)

    # ── Master Password Change ────────────────────────────────────────

    def _handle_change_password(self):
        """Change master password with proper vault key re-wrapping.

        Flow:
          1. Verify old password against stored hash
          2. Derive old KEK → unwrap vault key (verify crypto consistency)
          3. Hash new password → new auth hash
          4. Generate fresh KDF salt
          5. Derive new KEK from new password + new salt
          6. Re-wrap vault key with new KEK
          7. Atomically update: password_hash, kdf_salt, encrypted_vault_key,
             vault_key_nonce
        """
        old_pw = self.old_pwd.text()
        new_pw = self.new_pwd.text()
        confirm_pw = self.confirm_pwd.text()

        if not old_pw or not new_pw or not confirm_pw:
            self._show_message("All three fields are required.", True)
            return
        if len(new_pw) < 12:
            self._show_message("New password must be at least 12 characters.", True)
            return
        if new_pw != confirm_pw:
            self._show_message("New passwords do not match.", True)
            return
        if old_pw == new_pw:
            self._show_message("New password must differ from the current one.", True)
            return

        with Session() as session:
            user = session.query(User).filter_by(id=self.user_id).first()
            if not user:
                self._show_message("User not found.", True)
                return

            # Step 1: Verify old password
            if not verify_password(user.password_hash, old_pw):
                self._show_message("Current password is incorrect.", True)
                return

            # Step 2: Derive old KEK and unwrap vault key to verify crypto
            try:
                old_kek = derive_kek(old_pw, user.kdf_salt)
                vault_key = unwrap_vault_key(
                    user.encrypted_vault_key,
                    user.vault_key_nonce,
                    old_kek,
                )
            except Exception:
                self._show_message(
                    "Failed to unwrap vault key. Database may be corrupted.",
                    True,
                )
                return

            # Step 3: Hash new password
            new_hash = hash_password(new_pw)

            # Step 4: Generate fresh KDF salt
            new_kdf_salt = generate_salt()

            # Step 5: Derive new KEK
            new_kek = derive_kek(new_pw, new_kdf_salt)

            # Step 6: Re-wrap vault key with new KEK
            new_enc_vk, new_vk_nonce = wrap_vault_key(vault_key, new_kek)

            # Step 7: Atomic update
            user.password_hash = new_hash
            user.kdf_salt = new_kdf_salt
            user.encrypted_vault_key = new_enc_vk
            user.vault_key_nonce = new_vk_nonce
            session.commit()

        # Clear inputs
        self.old_pwd.clear()
        self.new_pwd.clear()
        self.confirm_pwd.clear()
        self._show_message("Master password updated successfully.")

    # ── Preferences ───────────────────────────────────────────────────

    def _handle_save_preferences(self):
        try:
            val = int(self.lock_timeout.text())
            if val < 30:
                self._show_message("Timeout must be at least 30 seconds.", True)
                return
            Config.VAULT_LOCK_SECONDS = val
            Config.save_settings()
            self.lock_timeout_changed.emit(val)
            self._show_message(f"Auto-lock set to {val} seconds.")
        except ValueError:
            self._show_message("Please enter a valid number.", True)

    # ── Export / Import ───────────────────────────────────────────────

    def _handle_export(self):
        """Export vault data to an encrypted .cipher file or plaintext CSV."""
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Vault",
            "cipher_backup",
            "Encrypted Vault (*.cipher);;CSV (*.csv)",
        )
        if not file_path:
            return

        try:
            from services.vault_io import export_vault_encrypted, export_vault_csv

            if selected_filter.startswith("CSV"):
                # Warn about plaintext export
                confirm = QMessageBox.warning(
                    self,
                    "Plaintext Export Warning",
                    "CSV export is NOT encrypted. Your passwords will be "
                    "saved in plain text.\n\nAre you sure you want to continue?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if confirm != QMessageBox.StandardButton.Yes:
                    return

                if not file_path.endswith(".csv"):
                    file_path += ".csv"
                export_vault_csv(self.user_id, self.vault_key, file_path)
            else:
                if not file_path.endswith(".cipher"):
                    file_path += ".cipher"
                export_vault_encrypted(
                    self.user_id, self.vault_key, file_path
                )

            self._show_message("Vault exported successfully.")
        except Exception as e:
            self._show_message(f"Export failed: {e}", True)

    def _handle_import(self):
        """Import vault data from an encrypted .cipher file or CSV."""
        file_path, selected_filter = QFileDialog.getOpenFileName(
            self,
            "Import Vault",
            "",
            "Encrypted Vault (*.cipher);;CSV (*.csv)",
        )
        if not file_path:
            return

        try:
            from services.vault_io import import_vault_encrypted, import_vault_csv

            if file_path.endswith(".csv"):
                count = import_vault_csv(
                    self.user_id, self.vault_key, file_path
                )
            else:
                count = import_vault_encrypted(
                    self.user_id, self.vault_key, file_path
                )

            self._show_message(f"Imported {count} entries successfully.")
        except Exception as e:
            self._show_message(f"Import failed: {e}", True)
