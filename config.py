import os
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Store database in user's AppData to avoid permission errors in Program Files
APP_DATA_DIR = os.path.join(os.getenv('LOCALAPPDATA', BASE_DIR), 'Cipher')
os.makedirs(APP_DATA_DIR, exist_ok=True)

dev_db = os.path.join(BASE_DIR, 'vault.db')
prod_db = os.path.join(APP_DATA_DIR, 'vault.db')

# Seamlessly migrate existing dev database if it exists
if os.path.exists(dev_db) and not os.path.exists(prod_db):
    try:
        shutil.copy2(dev_db, prod_db)
    except Exception:
        pass

import json

class Config:
    DATABASE_PATH = prod_db
    DATABASE_URI = f'sqlite:///{DATABASE_PATH}'

    # Argon2id parameters
    ARGON2_TIME_COST = 2
    ARGON2_MEMORY_COST = 102400  # 100MB
    ARGON2_PARALLELISM = 8

    # Preferences
    VAULT_LOCK_SECONDS = 300
    THEME = "dark"
    CUSTOM_THEME_COLORS = {}  # User overrides for custom theme tokens
    NATIVE_HOST_ALLOWED = True
    
    SETTINGS_FILE = os.path.join(APP_DATA_DIR, 'settings.json')

    @classmethod
    def load_settings(cls):
        if os.path.exists(cls.SETTINGS_FILE):
            try:
                with open(cls.SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    cls.VAULT_LOCK_SECONDS = data.get('lock_timeout', 300)
                    cls.THEME = data.get('theme', 'dark')
                    cls.CUSTOM_THEME_COLORS = data.get('custom_theme_colors', {})
                    cls.NATIVE_HOST_ALLOWED = data.get('native_host_allowed', True)
            except Exception:
                pass

    @classmethod
    def save_settings(cls):
        try:
            with open(cls.SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump({
                    'lock_timeout': cls.VAULT_LOCK_SECONDS,
                    'theme': cls.THEME,
                    'custom_theme_colors': cls.CUSTOM_THEME_COLORS,
                    'native_host_allowed': cls.NATIVE_HOST_ALLOWED
                }, f)
        except Exception:
            pass

# Load on module import
Config.load_settings()
