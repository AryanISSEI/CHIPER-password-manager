"""Cipher — Desktop Application Entry Point."""

import sys
from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QAction
from models import init_db
from config import Config
from gui.theme import ThemeManager
from gui.login_window import LoginWindow
from gui.main_window import MainWindow


def _create_tray_icon() -> QIcon:
    """Create a simple programmatic tray icon (diamond shape in accent blue)."""
    pixmap = QPixmap(64, 64)
    pixmap.fill(QColor(0, 0, 0, 0))  # Transparent background

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor("#2D7FF9"))
    painter.setPen(Qt.PenStyle.NoPen)

    # Diamond shape
    from PyQt6.QtGui import QPolygon
    from PyQt6.QtCore import QPoint
    diamond = QPolygon([
        QPoint(32, 4),   # top
        QPoint(60, 32),  # right
        QPoint(32, 60),  # bottom
        QPoint(4, 32),   # left
    ])
    painter.drawPolygon(diamond)
    painter.end()

    return QIcon(pixmap)


class CipherApp:
    """Application controller coordinating window transitions and lifecycle."""

    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setStyle("Fusion")
        ThemeManager.load_custom_colors(Config.CUSTOM_THEME_COLORS)
        ThemeManager.apply_theme(Config.THEME)
        self.app.setApplicationName("Cipher")

        # Don't quit when the last window closes (tray keeps app alive)
        self.app.setQuitOnLastWindowClosed(False)

        # Initialize SQLite database schema
        init_db()

        self.login_window = None
        self.main_window = None

        # ── System Tray ───────────────────────────────────────────────
        self.tray_icon = QSystemTrayIcon(_create_tray_icon(), self.app)
        self.tray_icon.setToolTip("Cipher — Password Manager")
        self._setup_tray_menu()
        self.tray_icon.show()

        # Double-click tray icon to show window
        self.tray_icon.activated.connect(self._on_tray_activated)

    def _setup_tray_menu(self):
        """Create the system tray context menu."""
        menu = QMenu()

        self.action_show = QAction("Show Cipher")
        self.action_show.triggered.connect(self._show_window)
        menu.addAction(self.action_show)

        self.action_lock = QAction("Lock Vault")
        self.action_lock.triggered.connect(self._lock_from_tray)
        self.action_lock.setEnabled(False)
        menu.addAction(self.action_lock)

        menu.addSeparator()

        action_quit = QAction("Quit")
        action_quit.triggered.connect(self._quit_app)
        menu.addAction(action_quit)

        self.tray_icon.setContextMenu(menu)

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._show_window()

    def _show_window(self):
        """Bring the current window to the foreground."""
        window = self.main_window or self.login_window
        if window:
            window.show()
            window.raise_()
            window.activateWindow()

    def _lock_from_tray(self):
        if self.main_window:
            self.main_window.lock_vault()

    def _quit_app(self):
        """Clean shutdown — zero vault key if still in memory."""
        if self.main_window:
            self.main_window.lock_vault()
        self.tray_icon.hide()
        self.app.quit()

    def show_login(self):
        if self.main_window:
            self.main_window.close()
            self.main_window = None

        self.action_lock.setEnabled(False)

        self.login_window = LoginWindow()
        self.login_window.authenticated.connect(self.show_main)
        self.login_window.show()

    def show_main(self, user_id: int, username: str, vault_key: bytes):
        if self.login_window:
            self.login_window.close()
            self.login_window = None

        self.main_window = MainWindow(user_id, username, vault_key)
        self.main_window.locked.connect(self.show_login)
        self.main_window.show()

        self.action_lock.setEnabled(True)
        self.tray_icon.showMessage(
            "Cipher", "Vault unlocked.",
            QSystemTrayIcon.MessageIcon.Information, 2000
        )

    def run(self) -> int:
        self.show_login()
        return self.app.exec()


from PyQt6.QtCore import QSharedMemory

def main():
    shared_mem = QSharedMemory("com.cipher.password_manager.lock")
    if shared_mem.attach():
        # Instance already running
        print("Cipher is already running. Exiting.")
        sys.exit(0)
    
    if not shared_mem.create(1):
        print("Failed to create shared memory lock. Exiting.")
        sys.exit(1)

    app = CipherApp()
    
    # Store reference so it's not garbage collected
    app._shared_mem = shared_mem

    sys.exit(app.run())


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    main()
