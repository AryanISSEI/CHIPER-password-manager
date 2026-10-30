"""Main application shell with sidebar navigation for Cipher."""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QStackedWidget, QFrame, QApplication, QSizePolicy,
    QGraphicsOpacityEffect
)
from PyQt6.QtCore import (
    Qt, QTimer, QObject, QEvent, pyqtSignal, QPropertyAnimation,
    QEasingCurve
)
from config import Config
from gui.theme import ThemeManager
from gui.vault_widget import VaultWidget
from gui.security_widget import SecurityWidget


class InactivityFilter(QObject):
    """Event filter attached to QApplication to detect user activity and reset auto-lock."""

    activity_detected = pyqtSignal()

    def eventFilter(self, obj, event):
        if event.type() in (
            QEvent.Type.KeyPress,
            QEvent.Type.KeyRelease,
            QEvent.Type.MouseButtonPress,
            QEvent.Type.MouseButtonRelease,
            QEvent.Type.MouseMove,
            QEvent.Type.Wheel
        ):
            self.activity_detected.emit()
        return super().eventFilter(obj, event)


class SidebarButton(QPushButton):
    """Navigation button for the sidebar with consistent styling."""

    def __init__(self, text: str, icon: str = "", parent=None):
        display_text = f"{icon}  {text}" if icon else text
        super().__init__(display_text, parent)
        self.setProperty("class", "nav")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(34)


class MainWindow(QMainWindow):
    """Authenticated shell containing sidebar navigation and content area with auto-lock."""

    locked = pyqtSignal()

    # Navigation page indices
    PAGE_ALL_ITEMS = 0
    PAGE_FAVORITES = 1
    PAGE_RECENT = 2
    PAGE_LOGINS = 3
    PAGE_CARDS = 4
    PAGE_NOTES = 5
    PAGE_IDENTITIES = 6
    PAGE_SECURITY = 7

    PAGE_SETTINGS = 8

    def __init__(self, user_id: int, username: str, vault_key: bytes):
        super().__init__()
        self.user_id = user_id
        self.username = username
        self.vault_key = bytearray(vault_key)  # Mutable bytearray for safe zeroing

        self._nav_buttons: list[SidebarButton] = []
        self._init_ui()
        self._setup_autolock()

    def _init_ui(self):
        self.setWindowTitle("Cipher")
        self.resize(1060, 720)
        self.setMinimumSize(820, 540)

        central_widget = QWidget()
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Sidebar ────────────────────────────────────────────────────
        sidebar = QFrame()
        sidebar.setProperty("class", "sidebar")
        sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(16, 20, 16, 16)
        sidebar_layout.setSpacing(0)

        # Brand
        brand_lbl = QLabel("◈  Cipher")
        brand_lbl.setProperty("class", "brand")
        brand_lbl.setContentsMargins(4, 0, 0, 0)
        sidebar_layout.addWidget(brand_lbl)
        sidebar_layout.addSpacing(28)

        # Global Add Item Button
        btn_add_global = QPushButton("+ Add Item")
        btn_add_global.setProperty("class", "primary")
        btn_add_global.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_add_global.setFixedHeight(36)
        btn_add_global.clicked.connect(self._open_global_add_dialog)
        sidebar_layout.addWidget(btn_add_global)
        sidebar_layout.addSpacing(20)

        # VAULT section
        vault_section = QLabel("VAULT")
        vault_section.setProperty("class", "nav-section")
        sidebar_layout.addWidget(vault_section)
        sidebar_layout.addSpacing(6)

        btn_all = SidebarButton("All Items", "○")
        btn_all.setChecked(True)
        btn_all.clicked.connect(lambda: self._navigate(self.PAGE_ALL_ITEMS))
        sidebar_layout.addWidget(btn_all)
        self._nav_buttons.append(btn_all)

        btn_fav = SidebarButton("Favorites", "○")
        btn_fav.clicked.connect(lambda: self._navigate(self.PAGE_FAVORITES))
        sidebar_layout.addWidget(btn_fav)
        self._nav_buttons.append(btn_fav)

        btn_recent = SidebarButton("Recently Used", "○")
        btn_recent.clicked.connect(lambda: self._navigate(self.PAGE_RECENT))
        sidebar_layout.addWidget(btn_recent)
        self._nav_buttons.append(btn_recent)

        sidebar_layout.addSpacing(20)

        # CATEGORIES section
        cat_section = QLabel("CATEGORIES")
        cat_section.setProperty("class", "nav-section")
        sidebar_layout.addWidget(cat_section)
        sidebar_layout.addSpacing(6)

        btn_logins = SidebarButton("Logins", "○")
        btn_logins.clicked.connect(lambda: self._navigate(self.PAGE_LOGINS))
        sidebar_layout.addWidget(btn_logins)
        self._nav_buttons.append(btn_logins)

        btn_cards = SidebarButton("Cards", "○")
        btn_cards.clicked.connect(lambda: self._navigate(self.PAGE_CARDS))
        sidebar_layout.addWidget(btn_cards)
        self._nav_buttons.append(btn_cards)

        btn_notes = SidebarButton("Secure Notes", "○")
        btn_notes.clicked.connect(lambda: self._navigate(self.PAGE_NOTES))
        sidebar_layout.addWidget(btn_notes)
        self._nav_buttons.append(btn_notes)

        btn_identities = SidebarButton("Identities", "○")
        btn_identities.clicked.connect(lambda: self._navigate(self.PAGE_IDENTITIES))
        sidebar_layout.addWidget(btn_identities)
        self._nav_buttons.append(btn_identities)

        sidebar_layout.addSpacing(20)

        # SECURITY section
        sec_section = QLabel("SECURITY")
        sec_section.setProperty("class", "nav-section")
        sidebar_layout.addWidget(sec_section)
        sidebar_layout.addSpacing(6)

        btn_security = SidebarButton("Security Checkup", "○")
        btn_security.clicked.connect(lambda: self._navigate(self.PAGE_SECURITY))
        sidebar_layout.addWidget(btn_security)
        self._nav_buttons.append(btn_security)

        # Spacer
        sidebar_layout.addStretch()

        # Bottom items
        btn_settings = SidebarButton("Settings", "⚙")
        btn_settings.clicked.connect(lambda: self._navigate(self.PAGE_SETTINGS))
        sidebar_layout.addWidget(btn_settings)
        self._nav_buttons.append(btn_settings)

        btn_account = QPushButton(f"👤  {self.username}")
        btn_account.setProperty("class", "nav-bottom")
        btn_account.setCursor(Qt.CursorShape.PointingHandCursor)
        sidebar_layout.addWidget(btn_account)

        main_layout.addWidget(sidebar)

        # ── Content Area ───────────────────────────────────────────────
        content_container = QWidget()
        content_layout = QVBoxLayout(content_container)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        # Top bar with vault status
        topbar = QFrame()
        c = ThemeManager.colors()
        topbar.setStyleSheet(f"background: transparent; border-bottom: 1px solid {c['border_subtle']};")
        self._topbar = topbar  # keep ref for theme updates
        topbar_layout = QHBoxLayout(topbar)
        topbar_layout.setContentsMargins(28, 12, 28, 12)

        topbar_layout.addStretch()

        # Vault lock indicator
        self.vault_status = QLabel("●  Vault unlocked")
        self.vault_status.setProperty("class", "vault-status")
        self.vault_status.setStyleSheet(f"color: {ThemeManager.colors()['success']}; font-size: 12px;")
        topbar_layout.addWidget(self.vault_status)

        topbar_layout.addSpacing(12)

        btn_lock = QPushButton("Lock")
        btn_lock.setProperty("class", "small-outline")
        btn_lock.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_lock.clicked.connect(self.lock_vault)
        topbar_layout.addWidget(btn_lock)

        content_layout.addWidget(topbar)

        # Stacked content
        self.stack = QStackedWidget()
        
        self.vault_widget = VaultWidget(self.user_id, bytes(self.vault_key))
        self.security_widget = SecurityWidget(self.user_id, bytes(self.vault_key))
        from gui.settings_widget import SettingsWidget
        self.settings_widget = SettingsWidget(
            self.user_id, bytes(self.vault_key)
        )
        self.settings_widget.lock_timeout_changed.connect(
            self._on_lock_timeout_changed
        )

        self.stack.addWidget(self.vault_widget)    # Index 0
        self.stack.addWidget(self.security_widget)  # Index 1
        self.stack.addWidget(self.settings_widget)  # Index 2

        content_layout.addWidget(self.stack)
        main_layout.addWidget(content_container)

        # Opacity effect for lock animation
        self.opacity_effect = QGraphicsOpacityEffect(central_widget)
        self.opacity_effect.setOpacity(1.0)
        central_widget.setGraphicsEffect(self.opacity_effect)

        self.setCentralWidget(central_widget)

    def _navigate(self, page_index: int):
        """Handle sidebar navigation instantly."""
        for i, btn in enumerate(self._nav_buttons):
            btn.setChecked(i == page_index)

        target_index = 0
        if page_index == self.PAGE_SECURITY:
            target_index = 1
        elif page_index == self.PAGE_SETTINGS:
            target_index = 2

        if self.stack.currentIndex() != target_index:
            self.stack.setCurrentIndex(target_index)
            self._apply_filter_for_page(page_index)
        else:
            self._apply_filter_for_page(page_index)

    def _apply_filter_for_page(self, page_index: int):
        if page_index == self.PAGE_SECURITY:
            self.security_widget.load_security_data()
        elif page_index == self.PAGE_SETTINGS:
            pass
        else:
            if page_index == self.PAGE_ALL_ITEMS:
                self.vault_widget.apply_filter(None)
            elif page_index == self.PAGE_FAVORITES:
                self.vault_widget.apply_filter('favorites')
            elif page_index == self.PAGE_RECENT:
                self.vault_widget.apply_filter('recent')
            elif page_index == self.PAGE_LOGINS:
                self.vault_widget.apply_filter('login')
            elif page_index == self.PAGE_CARDS:
                self.vault_widget.apply_filter('card')
            elif page_index == self.PAGE_NOTES:
                self.vault_widget.apply_filter('note')
            elif page_index == self.PAGE_IDENTITIES:
                self.vault_widget.apply_filter('identity')

    def _open_global_add_dialog(self):
        """Open the add entry dialog from anywhere in the app."""
        # Open via vault_widget to easily connect save signals
        self.vault_widget._open_add_dialog()

    def _setup_autolock(self):
        """Initializes the auto-lock inactivity timer."""
        self.lock_timer = QTimer(self)
        self.lock_timer.setInterval(Config.VAULT_LOCK_SECONDS * 1000)
        self.lock_timer.timeout.connect(self.lock_vault)
        self.lock_timer.start()

        # Install global activity watcher
        self.inactivity_filter = InactivityFilter()
        self.inactivity_filter.activity_detected.connect(self._reset_autolock)
        QApplication.instance().installEventFilter(self.inactivity_filter)

    def _reset_autolock(self):
        if self.lock_timer.isActive():
            self.lock_timer.start()  # Restarts timer

    def _on_lock_timeout_changed(self, seconds: int):
        """Update the auto-lock timer interval when user changes the setting."""
        self.lock_timer.setInterval(seconds * 1000)
        if self.lock_timer.isActive():
            self.lock_timer.start()  # Restart with new interval

    def lock_vault(self):
        """Dims the UI, zeroes the vault key, and returns to login."""
        self.lock_timer.stop()

        # Update status indicator
        self.vault_status.setText("●  Vault locked")
        self.vault_status.setStyleSheet(f"color: {ThemeManager.colors()['danger']}; font-size: 12px;")

        # Fade out animation (300ms)
        self.fade_anim = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_anim.setDuration(300)
        self.fade_anim.setStartValue(1.0)
        self.fade_anim.setEndValue(0.3)
        self.fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.fade_anim.finished.connect(self._finalize_lock)
        self.fade_anim.start()

    def _finalize_lock(self):
        """Complete the lock after fade animation."""
        # Cryptographically erase the vault key in memory
        for i in range(len(self.vault_key)):
            self.vault_key[i] = 0

        if hasattr(self, 'inactivity_filter'):
            QApplication.instance().removeEventFilter(self.inactivity_filter)

        self.locked.emit()
        self.close()

    def changeEvent(self, event):
        """Reload vault entries when the window regains focus so browser-captured credentials appear immediately."""
        try:
            if event.type() == QEvent.Type.ActivationChange and self.isActiveWindow():
                if hasattr(self, 'vault_widget') and hasattr(self, 'vault_key') and any(self.vault_key):
                    try:
                        self.vault_widget.load_entries()
                    except Exception:
                        pass
        except Exception:
            pass
        super().changeEvent(event)
