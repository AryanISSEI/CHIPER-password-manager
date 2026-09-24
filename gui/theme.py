"""Cipher — Multi-Theme Design System.

Supports Dark, Light, and Custom themes via token-based color dictionaries.
Typography: Geist → Inter → Segoe UI fallback chain.
Accent used ONLY for: primary buttons, active nav, focus states, links, security indicators.
"""

from __future__ import annotations

import copy
from typing import Optional

# ── Font Stack ──────────────────────────────────────────────────────────
FONT_FAMILY = "'Geist', 'Inter', 'Segoe UI', -apple-system, sans-serif"


# ══════════════════════════════════════════════════════════════════════════
# COLOR TOKEN PALETTES
# ══════════════════════════════════════════════════════════════════════════

DARK_COLORS = {
    # Backgrounds
    'bg':               '#0B0C0E',
    'surface':          '#121417',
    'elevated':         '#181B1F',

    # Gradients (main window background)
    'grad_start':       '#16191D',
    'grad_mid1':        '#111820',
    'grad_mid2':        '#0D1017',
    'grad_end':         '#0B0C0E',

    # Card gradients
    'card_grad_start':  '#151820',
    'card_grad_end':    '#111417',

    # Sidebar gradients
    'sidebar_grad_start': '#0E1013',
    'sidebar_grad_mid':   '#0B0C0E',
    'sidebar_grad_end':   '#090A0C',

    # Borders
    'border':           '#252930',
    'border_subtle':    '#1E2128',

    # Text
    'text_primary':     '#F5F5F5',
    'text_secondary':   '#9298A3',
    'text_muted':       '#5F6570',

    # Accent — electric blue (used sparingly)
    'accent':           '#2D7FF9',
    'accent_hover':     '#1A6FE8',
    'accent_pressed':   '#1560D4',
    'accent_subtle':    'rgba(45, 127, 249, 0.12)',
    'accent_selection': 'rgba(45, 127, 249, 0.3)',
    'accent_nav':       'rgba(45, 127, 249, 0.10)',
    'accent_combo_sel': 'rgba(45, 127, 249, 0.15)',

    # Primary button gradients
    'primary_grad_start': '#3D8FFF',
    'primary_grad_end':   '#1A6FE8',
    'primary_hover_start': '#2D7FF9',
    'primary_hover_end':   '#1560D4',
    'primary_pressed_start': '#1A6FE8',
    'primary_pressed_end':   '#0F50C0',

    # Semantic
    'danger':           '#E5484D',
    'danger_subtle':    'rgba(229, 72, 77, 0.12)',
    'danger_border':    'rgba(229, 72, 77, 0.3)',
    'danger_hover':     'rgba(229, 72, 77, 0.08)',
    'danger_border_btn': 'rgba(229, 72, 77, 0.25)',
    'success':          '#30A46C',
    'success_subtle':   'rgba(48, 164, 108, 0.10)',
    'success_border':   'rgba(48, 164, 108, 0.3)',
    'warning':          '#E5A63E',
    'warning_subtle':   'rgba(229, 166, 62, 0.12)',

    # Interactive
    'hover_overlay':    'rgba(255, 255, 255, 0.04)',
    'hover_overlay_subtle': 'rgba(255, 255, 255, 0.03)',
    'hover_overlay_micro':  'rgba(255, 255, 255, 0.02)',
    'border_hover':     '#363D47',

    # Progress bar
    'progress_bg':      '#1A1D22',

    # Strength gradients
    'strength_weak_start':   '#E5484D',
    'strength_weak_end':     '#C93B3F',
    'strength_fair_start':   '#E5A63E',
    'strength_fair_end':     '#D4932E',
    'strength_good_start':   '#2D7FF9',
    'strength_good_end':     '#1A6FE8',
    'strength_strong_start': '#30A46C',
    'strength_strong_end':   '#26925D',

    # Scrollbar
    'scrollbar_handle':       '#252930',
    'scrollbar_handle_hover': '#363D47',

    # Flash / info
    'info_bg':          'rgba(45, 127, 249, 0.10)',
    'info_border':      'rgba(45, 127, 249, 0.3)',

    # Message box
    'msgbox_bg':        '#121417',

    # Tooltip
    'tooltip_bg':       '#181B1F',
    'tooltip_border':   '#252930',
}


LIGHT_COLORS = {
    # Backgrounds
    'bg':               '#F4F5F7',
    'surface':          '#FFFFFF',
    'elevated':         '#F0F1F3',

    # Gradients (main window background)
    'grad_start':       '#F4F5F7',
    'grad_mid1':        '#EDEEF1',
    'grad_mid2':        '#F0F1F3',
    'grad_end':         '#F4F5F7',

    # Card gradients
    'card_grad_start':  '#FFFFFF',
    'card_grad_end':    '#FAFBFC',

    # Sidebar gradients
    'sidebar_grad_start': '#EBEDF0',
    'sidebar_grad_mid':   '#E8EAED',
    'sidebar_grad_end':   '#E4E6EA',

    # Borders
    'border':           '#D5D9E0',
    'border_subtle':    '#E2E5EA',

    # Text
    'text_primary':     '#1A1C1E',
    'text_secondary':   '#5F6570',
    'text_muted':       '#8B919D',

    # Accent — electric blue
    'accent':           '#2D7FF9',
    'accent_hover':     '#1A6FE8',
    'accent_pressed':   '#1560D4',
    'accent_subtle':    'rgba(45, 127, 249, 0.08)',
    'accent_selection': 'rgba(45, 127, 249, 0.2)',
    'accent_nav':       'rgba(45, 127, 249, 0.08)',
    'accent_combo_sel': 'rgba(45, 127, 249, 0.10)',

    # Primary button gradients
    'primary_grad_start': '#3D8FFF',
    'primary_grad_end':   '#1A6FE8',
    'primary_hover_start': '#2D7FF9',
    'primary_hover_end':   '#1560D4',
    'primary_pressed_start': '#1A6FE8',
    'primary_pressed_end':   '#0F50C0',

    # Semantic
    'danger':           '#DC3D43',
    'danger_subtle':    'rgba(220, 61, 67, 0.08)',
    'danger_border':    'rgba(220, 61, 67, 0.25)',
    'danger_hover':     'rgba(220, 61, 67, 0.06)',
    'danger_border_btn': 'rgba(220, 61, 67, 0.2)',
    'success':          '#28955F',
    'success_subtle':   'rgba(40, 149, 95, 0.08)',
    'success_border':   'rgba(40, 149, 95, 0.25)',
    'warning':          '#D4932E',
    'warning_subtle':   'rgba(212, 147, 46, 0.08)',

    # Interactive
    'hover_overlay':    'rgba(0, 0, 0, 0.04)',
    'hover_overlay_subtle': 'rgba(0, 0, 0, 0.03)',
    'hover_overlay_micro':  'rgba(0, 0, 0, 0.02)',
    'border_hover':     '#BFC4CC',

    # Progress bar
    'progress_bg':      '#E2E5EA',

    # Strength gradients
    'strength_weak_start':   '#DC3D43',
    'strength_weak_end':     '#C93B3F',
    'strength_fair_start':   '#D4932E',
    'strength_fair_end':     '#C08525',
    'strength_good_start':   '#2D7FF9',
    'strength_good_end':     '#1A6FE8',
    'strength_strong_start': '#28955F',
    'strength_strong_end':   '#1F8050',

    # Scrollbar
    'scrollbar_handle':       '#C8CCD3',
    'scrollbar_handle_hover': '#B0B5BE',

    # Flash / info
    'info_bg':          'rgba(45, 127, 249, 0.08)',
    'info_border':      'rgba(45, 127, 249, 0.25)',

    # Message box
    'msgbox_bg':        '#FFFFFF',

    # Tooltip
    'tooltip_bg':       '#FFFFFF',
    'tooltip_border':   '#D5D9E0',
}


# ══════════════════════════════════════════════════════════════════════════
# STYLESHEET TEMPLATE BUILDER
# ══════════════════════════════════════════════════════════════════════════

def _build_stylesheet(c: dict) -> str:
    """Generate the full Qt stylesheet from a color token dictionary."""
    return f"""
/* ══════════════════════════════════════════════════════════════════════
   CIPHER — Multi-Theme Design System
   ══════════════════════════════════════════════════════════════════════ */

/* ── Global Reset ──────────────────────────────────────────────────── */
QWidget {{
    font-family: {FONT_FAMILY};
    font-size: 14px;
    color: {c['text_primary']};
    outline: none;
}}

QMainWindow, QDialog {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0    {c['grad_start']},
        stop:0.35 {c['grad_mid1']},
        stop:0.65 {c['grad_mid2']},
        stop:1    {c['grad_end']}
    );
}}

/* ── Labels ────────────────────────────────────────────────────────── */
QLabel {{
    color: {c['text_primary']};
    background: transparent;
}}

QLabel[class="muted"] {{
    color: {c['text_secondary']};
    font-size: 13px;
}}

QLabel[class="metadata"] {{
    color: {c['text_muted']};
    font-size: 12px;
}}

QLabel[class="title"] {{
    font-size: 32px;
    font-weight: 600;
    color: {c['text_primary']};
    letter-spacing: -0.5px;
}}

QLabel[class="section"] {{
    font-size: 18px;
    font-weight: 500;
    color: {c['text_primary']};
}}

QLabel[class="subtitle"] {{
    font-size: 16px;
    font-weight: 500;
    color: {c['text_primary']};
}}

QLabel[class="credential-name"] {{
    font-size: 15px;
    font-weight: 500;
    color: {c['text_primary']};
}}

QLabel[class="nav-section"] {{
    font-size: 11px;
    font-weight: 600;
    color: {c['text_muted']};
    letter-spacing: 1px;
    padding-left: 4px;
}}

QLabel[class="brand"] {{
    font-size: 18px;
    font-weight: 600;
    color: {c['text_primary']};
    letter-spacing: -0.3px;
}}

QLabel[class="greeting"] {{
    font-size: 22px;
    font-weight: 500;
    color: {c['text_primary']};
}}

QLabel[class="vault-status"] {{
    font-size: 13px;
    color: {c['text_secondary']};
}}

/* ── Line Edits ────────────────────────────────────────────────────── */
QLineEdit, QTextEdit {{
    background-color: {c['surface']};
    border: 1px solid {c['border']};
    border-radius: 6px;
    padding: 9px 12px;
    color: {c['text_primary']};
    font-size: 14px;
    selection-background-color: {c['accent_selection']};
}}

QLineEdit:focus, QTextEdit:focus {{
    border-color: {c['accent']};
}}

QLineEdit:read-only {{
    background-color: {c['bg']};
    color: {c['text_secondary']};
    border-color: {c['border_subtle']};
}}

QLineEdit[class="search"] {{
    background-color: {c['surface']};
    border: 1px solid {c['border']};
    border-radius: 8px;
    padding: 11px 14px;
    font-size: 14px;
}}

/* ── Push Buttons ──────────────────────────────────────────────────── */
QPushButton {{
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 500;
    font-size: 13px;
    border: none;
    background: transparent;
    color: {c['text_primary']};
}}

QPushButton[class="primary"] {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {c['primary_grad_start']},
        stop:1 {c['primary_grad_end']}
    );
    color: white;
    font-weight: 600;
    padding: 9px 20px;
}}

QPushButton[class="primary"]:hover {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {c['primary_hover_start']},
        stop:1 {c['primary_hover_end']}
    );
}}

QPushButton[class="primary"]:pressed {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {c['primary_pressed_start']},
        stop:1 {c['primary_pressed_end']}
    );
}}

QPushButton[class="outline"] {{
    background-color: transparent;
    color: {c['text_primary']};
    border: 1px solid {c['border']};
}}

QPushButton[class="outline"]:hover {{
    background-color: {c['hover_overlay']};
    border-color: {c['border_hover']};
}}

QPushButton[class="danger"] {{
    background-color: transparent;
    color: {c['danger']};
    border: 1px solid {c['danger_border']};
}}

QPushButton[class="danger"]:hover {{
    background-color: {c['danger_hover']};
}}

QPushButton[class="small-outline"] {{
    background: transparent;
    color: {c['text_secondary']};
    border: 1px solid {c['border']};
    padding: 5px 10px;
    font-size: 12px;
    border-radius: 5px;
    font-weight: 500;
}}

QPushButton[class="small-outline"]:hover {{
    color: {c['text_primary']};
    background: {c['hover_overlay']};
    border-color: {c['border_hover']};
}}

QPushButton[class="small-danger"] {{
    background: transparent;
    color: {c['danger']};
    border: 1px solid {c['danger_border_btn']};
    padding: 5px 10px;
    font-size: 12px;
    border-radius: 5px;
}}

QPushButton[class="small-danger"]:hover {{
    background: {c['danger_hover']};
}}

/* Sidebar navigation items */
QPushButton[class="nav"] {{
    background: transparent;
    color: {c['text_secondary']};
    padding: 7px 12px;
    border-radius: 6px;
    font-weight: 400;
    font-size: 13px;
    text-align: left;
}}

QPushButton[class="nav"]:hover {{
    color: {c['text_primary']};
    background: {c['hover_overlay']};
}}

QPushButton[class="nav"]:checked {{
    color: {c['text_primary']};
    background: {c['accent_nav']};
}}

QPushButton[class="nav-bottom"] {{
    background: transparent;
    color: {c['text_muted']};
    padding: 6px 12px;
    border-radius: 6px;
    font-weight: 400;
    font-size: 12px;
    text-align: left;
}}

QPushButton[class="nav-bottom"]:hover {{
    color: {c['text_secondary']};
    background: {c['hover_overlay_subtle']};
}}

/* Text link-style button */
QPushButton[class="link"] {{
    background: transparent;
    color: {c['accent']};
    border: none;
    padding: 0;
    font-size: 13px;
    font-weight: 500;
}}

QPushButton[class="link"]:hover {{
    color: {c['accent_hover']};
}}

/* ── Theme selector buttons ───────────────────────────────────────── */
QPushButton[class="theme-option"] {{
    background: {c['surface']};
    color: {c['text_secondary']};
    border: 1px solid {c['border']};
    border-radius: 8px;
    padding: 10px 18px;
    font-size: 13px;
    font-weight: 500;
}}

QPushButton[class="theme-option"]:hover {{
    border-color: {c['border_hover']};
    background: {c['hover_overlay']};
}}

QPushButton[class="theme-option"]:checked {{
    border-color: {c['accent']};
    color: {c['accent']};
    background: {c['accent_subtle']};
}}

/* ── Frames / Cards ────────────────────────────────────────────────── */
QFrame[class="card"] {{
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 {c['card_grad_start']},
        stop:1 {c['card_grad_end']}
    );
    border: 1px solid {c['border']};
    border-radius: 8px;
}}

QFrame[class="surface"] {{
    background-color: {c['surface']};
    border: none;
    border-radius: 0;
}}

QFrame[class="elevated"] {{
    background-color: {c['elevated']};
    border: 1px solid {c['border']};
    border-radius: 8px;
}}

QFrame[class="separator"] {{
    background-color: {c['border']};
    max-height: 1px;
}}

QFrame[class="sidebar"] {{
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0   {c['sidebar_grad_start']},
        stop:0.5 {c['sidebar_grad_mid']},
        stop:1   {c['sidebar_grad_end']}
    );
    border-right: 1px solid {c['border_subtle']};
}}

/* Credential list row */
QFrame[class="credential-row"] {{
    background: transparent;
    border-bottom: 1px solid {c['border_subtle']};
    border-radius: 0;
    padding: 0;
}}

QFrame[class="credential-row"]:hover {{
    background: {c['hover_overlay_micro']};
}}

/* ── Scroll Areas ──────────────────────────────────────────────────── */
QScrollArea {{
    background: transparent;
    border: none;
}}

QScrollArea > QWidget > QWidget {{
    background: transparent;
}}

QScrollBar:vertical {{
    border: none;
    background: transparent;
    width: 6px;
    margin: 4px 2px;
}}

QScrollBar::handle:vertical {{
    background: {c['scrollbar_handle']};
    border-radius: 3px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background: {c['scrollbar_handle_hover']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
    background: transparent;
}}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: transparent;
}}

QScrollBar:horizontal {{
    border: none;
    background: transparent;
    height: 6px;
    margin: 2px 4px;
}}

QScrollBar::handle:horizontal {{
    background: {c['scrollbar_handle']};
    border-radius: 3px;
    min-width: 30px;
}}

QScrollBar::handle:horizontal:hover {{
    background: {c['scrollbar_handle_hover']};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
    background: transparent;
}}

QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
    background: transparent;
}}

/* ── Check Boxes ───────────────────────────────────────────────────── */
QCheckBox {{
    color: {c['text_primary']};
    spacing: 8px;
    font-size: 13px;
}}

QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {c['border']};
    border-radius: 4px;
    background: {c['surface']};
}}

QCheckBox::indicator:hover {{
    border-color: {c['border_hover']};
}}

QCheckBox::indicator:checked {{
    background: {c['accent']};
    border-color: {c['accent']};
}}

/* ── Sliders ───────────────────────────────────────────────────────── */
QSlider::groove:horizontal {{
    border: none;
    height: 4px;
    background: {c['border']};
    border-radius: 2px;
}}

QSlider::handle:horizontal {{
    background: {c['accent']};
    border: none;
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 7px;
}}

QSlider::sub-page:horizontal {{
    background: {c['accent']};
    border-radius: 2px;
}}

/* ── Combo Box ─────────────────────────────────────────────────────── */
QComboBox {{
    background-color: {c['surface']};
    border: 1px solid {c['border']};
    border-radius: 6px;
    padding: 8px 12px;
    color: {c['text_primary']};
    font-size: 13px;
}}

QComboBox:focus {{
    border-color: {c['accent']};
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox::down-arrow {{
    image: none;
    border: none;
}}

QComboBox QAbstractItemView {{
    background-color: {c['elevated']};
    border: 1px solid {c['border']};
    selection-background-color: {c['accent_combo_sel']};
    color: {c['text_primary']};
    outline: none;
    padding: 4px;
}}

/* ── Progress Bar ──────────────────────────────────────────────────── */
QProgressBar {{
    background: {c['progress_bg']};
    border-radius: 3px;
    border: none;
    max-height: 6px;
    min-height: 6px;
    text-align: center;
}}

QProgressBar::chunk {{
    border-radius: 3px;
}}

/* Strength bar — Weak (red gradient) */
QProgressBar[strength="weak"]::chunk {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {c['strength_weak_start']},
        stop:1 {c['strength_weak_end']}
    );
}}

/* Strength bar — Fair (orange gradient) */
QProgressBar[strength="fair"]::chunk {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {c['strength_fair_start']},
        stop:1 {c['strength_fair_end']}
    );
}}

/* Strength bar — Good (blue gradient) */
QProgressBar[strength="good"]::chunk {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {c['strength_good_start']},
        stop:1 {c['strength_good_end']}
    );
}}

/* Strength bar — Strong / Very Strong (green gradient) */
QProgressBar[strength="strong"]::chunk {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {c['strength_strong_start']},
        stop:1 {c['strength_strong_end']}
    );
}}

/* ── Flash / Toast Messages ────────────────────────────────────────── */
QLabel[class="flash-success"] {{
    background-color: {c['success_subtle']};
    border: 1px solid {c['success_border']};
    color: {c['success']};
    border-radius: 6px;
    padding: 9px 14px;
    font-size: 13px;
}}

QLabel[class="flash-danger"] {{
    background-color: {c['danger_subtle']};
    border: 1px solid {c['danger_border']};
    color: {c['danger']};
    border-radius: 6px;
    padding: 9px 14px;
    font-size: 13px;
}}

QLabel[class="flash-info"] {{
    background-color: {c['info_bg']};
    border: 1px solid {c['info_border']};
    color: {c['accent']};
    border-radius: 6px;
    padding: 9px 14px;
    font-size: 13px;
}}

/* ── Message Box ───────────────────────────────────────────────────── */
QMessageBox {{
    background-color: {c['msgbox_bg']};
}}

QMessageBox QLabel {{
    color: {c['text_primary']};
}}

QMessageBox QPushButton {{
    background-color: {c['accent']};
    color: white;
    padding: 7px 20px;
    border-radius: 6px;
    font-weight: 500;
    min-width: 72px;
}}

QMessageBox QPushButton:hover {{
    background-color: {c['accent_hover']};
}}

/* ── Tooltip ───────────────────────────────────────────────────────── */
QToolTip {{
    background-color: {c['tooltip_bg']};
    color: {c['text_primary']};
    border: 1px solid {c['tooltip_border']};
    padding: 5px 8px;
    border-radius: 4px;
    font-size: 12px;
}}
"""


# ══════════════════════════════════════════════════════════════════════════
# THEME MANAGER
# ══════════════════════════════════════════════════════════════════════════

class ThemeManager:
    """Centralized theme controller for the application.

    Usage:
        ThemeManager.apply_theme("dark")   # on startup
        ThemeManager.apply_theme("light")  # from settings
        c = ThemeManager.colors()          # for inline styles
    """

    _BUILTIN_THEMES: dict[str, dict] = {
        'dark':  DARK_COLORS,
        'light': LIGHT_COLORS,
    }

    _current_theme: str = 'dark'
    _current_colors: dict = DARK_COLORS
    _custom_colors: dict = {}  # User overrides for custom theme

    @classmethod
    def get_themes(cls) -> list[str]:
        """Return available theme names."""
        return ['dark', 'light', 'custom']

    @classmethod
    def get_current_theme(cls) -> str:
        """Return the name of the active theme."""
        return cls._current_theme

    @classmethod
    def colors(cls) -> dict:
        """Return the active color token dictionary.

        Use this for inline styles that can't be handled by the global stylesheet,
        e.g. `widget.setStyleSheet(f"color: {ThemeManager.colors()['success']};")`.
        """
        return cls._current_colors

    @classmethod
    def apply_theme(cls, name: str) -> None:
        """Apply a theme by name. Updates the QApplication stylesheet globally."""
        from PyQt6.QtWidgets import QApplication

        if name == 'custom':
            # Start from dark, overlay user overrides
            colors = copy.deepcopy(DARK_COLORS)
            colors.update(cls._custom_colors)
        elif name in cls._BUILTIN_THEMES:
            colors = cls._BUILTIN_THEMES[name]
        else:
            # Fallback to dark
            name = 'dark'
            colors = DARK_COLORS

        cls._current_theme = name
        cls._current_colors = colors

        app = QApplication.instance()
        if app:
            app.setStyleSheet(_build_stylesheet(colors))

    @classmethod
    def get_custom_colors(cls) -> dict:
        """Return the full resolved custom color dict (dark base + overrides)."""
        merged = copy.deepcopy(DARK_COLORS)
        merged.update(cls._custom_colors)
        return merged

    @classmethod
    def set_custom_color(cls, key: str, value: str) -> None:
        """Set a single custom theme override and re-apply if custom is active."""
        cls._custom_colors[key] = value
        if cls._current_theme == 'custom':
            cls.apply_theme('custom')

    @classmethod
    def reset_custom_theme(cls) -> None:
        """Clear all custom overrides and re-apply if custom is active."""
        cls._custom_colors.clear()
        if cls._current_theme == 'custom':
            cls.apply_theme('custom')

    @classmethod
    def load_custom_colors(cls, overrides: dict) -> None:
        """Load custom color overrides (called from Config on startup)."""
        if isinstance(overrides, dict):
            cls._custom_colors = overrides

    @classmethod
    def save_custom_colors(cls) -> dict:
        """Return custom color overrides for persistence."""
        return copy.deepcopy(cls._custom_colors)


# ── Backward Compatibility ──────────────────────────────────────────────
# Other modules that `from gui.theme import STYLESHEET` still work during
# the transition. This generates the dark stylesheet at import time.
STYLESHEET = _build_stylesheet(DARK_COLORS)

# Also export COLORS for any code referencing it directly
COLORS = DARK_COLORS
