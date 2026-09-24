"""Security Checkup widget for Cipher.

Stripped-down design: score, simple issue list, recommendations.
No stat card grid, no full breakdown table — just the essentials.
"""

import hashlib
from collections import Counter
from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea
)
from PyQt6.QtCore import Qt, QRectF, QObject, QThread, pyqtSignal
from PyQt6.QtGui import QPainter, QColor, QPen, QFont
from models import Session
from models.vault import VaultEntry
from services.crypto import decrypt_data
from services.password_generator import calculate_password_strength
from services.breach_check import check_password_breach
from gui.theme import ThemeManager


class BulkBreachCheckWorker(QObject):
    """Check multiple passwords against HIBP in a background thread."""

    finished = pyqtSignal(int)    # compromised_count
    progress = pyqtSignal(str)    # status text updates

    def __init__(self, passwords: list[str]):
        super().__init__()
        self._passwords = passwords
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        compromised = 0
        total = len(self._passwords)
        for i, pwd in enumerate(self._passwords, 1):
            if self._is_cancelled:
                break
            self.progress.emit(f"Checking breaches… {i}/{total}")
            try:
                is_breached, _ = check_password_breach(pwd)
                if is_breached:
                    compromised += 1
            except Exception:
                pass  # Network errors are non-fatal for bulk checks
        self.finished.emit(compromised)


class ScoreGauge(QWidget):
    """Minimal circular score gauge."""

    def __init__(self, score: int = 100, parent=None):
        super().__init__(parent)
        self.score = score
        self.setFixedSize(90, 90)

    def set_score(self, score: int):
        self.score = score
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = QRectF(8, 8, 74, 74)
        c = ThemeManager.colors()

        # Background track
        bg_pen = QPen(QColor(c['border']), 6)
        bg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(bg_pen)
        painter.drawArc(rect, 0, 360 * 16)

        # Score arc
        if self.score >= 80:
            color = QColor(c['success'])
        elif self.score >= 60:
            color = QColor(c['accent'])
        elif self.score >= 40:
            color = QColor(c['warning'])
        else:
            color = QColor(c['danger'])

        fg_pen = QPen(color, 6)
        fg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(fg_pen)
        span_angle = int(-(self.score / 100.0) * 360 * 16)
        painter.drawArc(rect, 90 * 16, span_angle)

        # Score text
        painter.setPen(QColor(c['text_primary']))
        font = QFont("Geist", 14, QFont.Weight.DemiBold)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, str(self.score))


class IssueRow(QFrame):
    """A single issue row in the security checkup."""

    def __init__(self, count: int, label: str, parent=None):
        super().__init__(parent)
        self.setProperty("class", "credential-row")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 12, 4, 12)
        layout.setSpacing(8)

        count_lbl = QLabel(str(count))
        c = ThemeManager.colors()
        count_lbl.setStyleSheet(
            f"font-size: 15px; font-weight: 600; "
            f"color: {c['danger'] if count > 0 else c['success']};"
        )
        count_lbl.setFixedWidth(24)
        layout.addWidget(count_lbl)

        text_lbl = QLabel(label)
        text_lbl.setStyleSheet(f"font-size: 14px; color: {ThemeManager.colors()['text_primary']};")
        layout.addWidget(text_lbl)

        layout.addStretch()

        arrow = QLabel("→")
        arrow.setStyleSheet(f"color: {ThemeManager.colors()['text_muted']}; font-size: 14px;")
        layout.addWidget(arrow)


class SecurityWidget(QWidget):
    """Security Checkup — score + issue summary + recommendations."""

    def __init__(self, user_id: int, vault_key: bytes, parent=None):
        super().__init__(parent)
        self.user_id = user_id
        self.vault_key = vault_key
        self._breach_thread: QThread | None = None
        self._breach_worker: BulkBreachCheckWorker | None = None
        self._pending_analysis: list = []
        self._pending_total: int = 0
        self._pending_weak: int = 0
        self._pending_reused: int = 0
        self._init_ui()
        self.load_security_data()

    def _init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        self.content_layout = QVBoxLayout(content)
        self.content_layout.setContentsMargins(32, 28, 32, 28)
        self.content_layout.setSpacing(0)

        # Title
        title_lbl = QLabel("Security Checkup")
        title_lbl.setProperty("class", "section")
        self.content_layout.addWidget(title_lbl)
        self.content_layout.addSpacing(28)

        # Score section
        score_row = QHBoxLayout()
        score_row.setSpacing(20)

        self.gauge = ScoreGauge(100)
        score_row.addWidget(self.gauge)

        score_text_layout = QVBoxLayout()
        score_text_layout.setSpacing(4)

        self.score_label = QLabel("Your vault")
        self.score_label.setProperty("class", "muted")
        score_text_layout.addWidget(self.score_label)

        self.score_value = QLabel("100 / 100")
        self.score_value.setStyleSheet(f"font-size: 24px; font-weight: 600; color: {ThemeManager.colors()['text_primary']};")
        score_text_layout.addWidget(self.score_value)

        self.verdict_lbl = QLabel("Excellent")
        self.verdict_lbl.setStyleSheet(f"font-size: 14px; font-weight: 500; color: {ThemeManager.colors()['success']};")
        score_text_layout.addWidget(self.verdict_lbl)

        score_row.addLayout(score_text_layout)
        score_row.addStretch()

        self.content_layout.addLayout(score_row)
        self.content_layout.addSpacing(32)

        # Separator
        sep = QFrame()
        sep.setProperty("class", "separator")
        sep.setFixedHeight(1)
        self.content_layout.addWidget(sep)
        self.content_layout.addSpacing(24)

        # Issue rows container
        self.issues_layout = QVBoxLayout()
        self.issues_layout.setSpacing(0)
        self.content_layout.addLayout(self.issues_layout)
        self.content_layout.addSpacing(24)

        # Separator
        sep2 = QFrame()
        sep2.setProperty("class", "separator")
        sep2.setFixedHeight(1)
        self.content_layout.addWidget(sep2)
        self.content_layout.addSpacing(24)

        # Recommendations
        rec_title = QLabel("Recommendations")
        rec_title.setProperty("class", "section")
        self.content_layout.addWidget(rec_title)
        self.content_layout.addSpacing(12)

        self.rec_layout = QVBoxLayout()
        self.rec_layout.setSpacing(8)
        self.content_layout.addLayout(self.rec_layout)

        self.content_layout.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)

    def load_security_data(self):
        """Audit all credentials and update the display."""
        # Clear issue rows
        while self.issues_layout.count():
            item = self.issues_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Clear recommendations
        while self.rec_layout.count():
            item = self.rec_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        with Session() as session:
            entries = session.query(VaultEntry).filter_by(user_id=self.user_id).all()

            passwords = []
            plaintext_passwords = []
            analysis_list = []

            for entry in entries:
                try:
                    title = decrypt_data(entry.encrypted_title, entry.nonce_title, self.vault_key)
                    pwd = decrypt_data(entry.encrypted_password, entry.nonce_password, self.vault_key)
                    strength = calculate_password_strength(pwd)

                    pw_hash = hashlib.sha256(pwd.encode()).hexdigest()
                    passwords.append(pw_hash)
                    plaintext_passwords.append(pwd)

                    analysis_list.append({
                        'title': title,
                        'strength': strength,
                        'pw_hash': pw_hash,
                    })
                except Exception:
                    pass

        # Aggregation
        hash_counts = Counter(passwords)
        reused_hashes = {h for h, c in hash_counts.items() if c > 1}

        total = len(analysis_list)
        weak_count = sum(1 for e in analysis_list if e['strength']['score'] < 40)
        reused_count = sum(1 for e in analysis_list if e['pw_hash'] in reused_hashes)

        # Store pending state for when breach check completes
        self._pending_total = total
        self._pending_weak = weak_count
        self._pending_reused = reused_count

        # Show initial UI with "checking..." for compromised
        self._update_score_ui(total, weak_count, reused_count, compromised_count=None)

        # Issue rows (compromised shows loading state)
        self.issues_layout.addWidget(IssueRow(weak_count, "Weak passwords"))
        self.issues_layout.addWidget(IssueRow(reused_count, "Reused passwords"))
        self._compromised_row = IssueRow(0, "Compromised passwords  ·  checking…")
        self.issues_layout.addWidget(self._compromised_row)

        # Start async breach checking for unique passwords
        unique_passwords = list(set(plaintext_passwords))
        if unique_passwords:
            self._start_breach_check(unique_passwords)
        else:
            self._on_breach_check_done(0)

    def _start_breach_check(self, passwords: list[str]):
        """Run bulk breach check in background thread."""
        # Cancel any existing check gracefully
        if self._breach_worker:
            self._breach_worker.cancel()
        if self._breach_thread and self._breach_thread.isRunning():
            self._breach_thread.quit()
            self._breach_thread.wait()

        self._breach_thread = QThread()
        self._breach_worker = BulkBreachCheckWorker(passwords)
        self._breach_worker.moveToThread(self._breach_thread)

        self._breach_thread.started.connect(self._breach_worker.run)
        self._breach_worker.finished.connect(self._on_breach_check_done)
        
        # Proper memory management: thread and worker delete themselves
        self._breach_worker.finished.connect(self._breach_thread.quit)
        self._breach_thread.finished.connect(self._breach_worker.deleteLater)
        self._breach_thread.finished.connect(self._breach_thread.deleteLater)

        self._breach_thread.start()

    def _on_breach_check_done(self, compromised_count: int):
        """Update UI after breach check completes."""
        # Replace the compromised row
        if self._compromised_row:
            self._compromised_row.deleteLater()

        self._compromised_row = IssueRow(compromised_count, "Compromised passwords")
        self.issues_layout.addWidget(self._compromised_row)

        # Recalculate score with real compromised count
        self._update_score_ui(
            self._pending_total,
            self._pending_weak,
            self._pending_reused,
            compromised_count,
        )

        # Update recommendations
        while self.rec_layout.count():
            item = self.rec_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        recommendations = []
        if compromised_count > 0:
            recommendations.append("Change your compromised passwords immediately")
        if self._pending_reused > 0:
            recommendations.append("Change your reused passwords")
        if self._pending_weak > 0:
            recommendations.append("Strengthen your weak passwords")
        if self._pending_total == 0:
            recommendations.append("Add credentials to your vault")
        if not recommendations:
            recommendations.append("Your vault is in great shape")

        for rec in recommendations:
            lbl = QLabel(f"●  {rec}")
            lbl.setStyleSheet(f"color: {ThemeManager.colors()['text_secondary']}; font-size: 13px; padding-left: 4px;")
            self.rec_layout.addWidget(lbl)

    def _update_score_ui(self, total: int, weak_count: int,
                         reused_count: int, compromised_count: int | None):
        """Update score gauge and verdict label."""
        if total == 0:
            score = 100
        else:
            deductions = 0
            deductions += (weak_count / total) * 35
            deductions += (reused_count / total) * 25
            if compromised_count is not None:
                deductions += (compromised_count / total) * 40
            score = max(0, int(100 - deductions))

        self.gauge.set_score(score)
        self.score_value.setText(f"{score} / 100")

        c = ThemeManager.colors()
        if score >= 80:
            self.verdict_lbl.setText("Excellent")
            self.verdict_lbl.setStyleSheet(f"font-size: 14px; font-weight: 500; color: {c['success']};")
        elif score >= 60:
            self.verdict_lbl.setText("Good")
            self.verdict_lbl.setStyleSheet(f"font-size: 14px; font-weight: 500; color: {c['accent']};")
        elif score >= 40:
            self.verdict_lbl.setText("Needs attention")
            self.verdict_lbl.setStyleSheet(f"font-size: 14px; font-weight: 500; color: {c['warning']};")
        else:
            self.verdict_lbl.setText("At risk")
            self.verdict_lbl.setStyleSheet(f"font-size: 14px; font-weight: 500; color: {c['danger']};")


