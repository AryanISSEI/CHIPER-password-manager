"""Cipher — Native Messaging Host Installer for Google Chrome (Windows, macOS, Linux).

Registers or unregisters the Cipher native messaging host with Google Chrome
by writing the manifest path to the Windows Registry:
  HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.cipher.password_manager

Usage:
  python install_native_host.py                  # Install / register for Google Chrome
  python install_native_host.py --uninstall       # Remove registration
  python install_native_host.py --extension-id ID # Register with specific extension ID
"""

import os
import sys
import json
import argparse

HOST_NAME = "com.cipher.password_manager"
DEFAULT_EXTENSION_ID = "dhmkinmiippfgmcdllobdhkkfccpkaan"
FIREFOX_EXTENSION_ID = "cipher-password-manager@local"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MANIFEST_PATH = os.path.join(SCRIPT_DIR, "com.cipher.password_manager.json")
FIREFOX_MANIFEST_PATH = os.path.join(SCRIPT_DIR, "com.cipher.password_manager.firefox.json")
BAT_PATH = os.path.join(SCRIPT_DIR, "cipher_native_host.bat")
PY_SCRIPT = os.path.join(SCRIPT_DIR, "cipher_native_host.py")


def update_manifest_and_bat(extension_ids=None):
    """Ensure paths in the batch wrapper and JSON manifests match the current location."""
    python_exe = sys.executable

    # Write wrapper .bat for Windows
    bat_content = f"""@echo off
setlocal
"{python_exe}" -u "{PY_SCRIPT}" %*
"""
    with open(BAT_PATH, "w", encoding="utf-8") as f:
        f.write(bat_content)

    if not extension_ids:
        extension_ids = [DEFAULT_EXTENSION_ID]

    # Chrome Manifest: Allowed origins must end with a trailing slash
    allowed_origins = [
        f"chrome-extension://{ext_id.rstrip('/')}/"
        for ext_id in extension_ids
    ]

    manifest_data = {
        "name": HOST_NAME,
        "description": "Cipher Password Manager Native Messaging Host",
        "path": BAT_PATH if sys.platform == "win32" else PY_SCRIPT,
        "type": "stdio",
        "allowed_origins": allowed_origins,
    }
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    # Firefox Manifest: Allowed extensions array with Gecko ID
    firefox_manifest_data = {
        "name": HOST_NAME,
        "description": "Cipher Password Manager Native Messaging Host",
        "path": BAT_PATH if sys.platform == "win32" else PY_SCRIPT,
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID],
    }
    with open(FIREFOX_MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(firefox_manifest_data, f, indent=2)

    print(f"[OK] Generated wrapper batch file at: {BAT_PATH}")
    print(f"[OK] Updated Chrome manifest at: {MANIFEST_PATH}")
    print(f"[OK] Updated Firefox manifest at: {FIREFOX_MANIFEST_PATH}")


def install_windows(extension_ids=None):
    """Register native messaging host in HKCU registry for Google Chrome and Mozilla Firefox."""
    import winreg

    update_manifest_and_bat(extension_ids)

    # 1. Register for Google Chrome
    chrome_sub_key = rf"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}"
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, chrome_sub_key) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, MANIFEST_PATH)
        print(f"[SUCCESS] Registered native host for Google Chrome:")
        print(f"          HKCU\\{chrome_sub_key} -> {MANIFEST_PATH}")
    except Exception as e:
        print(f"[ERROR] Failed to write Chrome registry key: {e}", file=sys.stderr)

    # 2. Register for Mozilla Firefox
    firefox_sub_key = rf"Software\Mozilla\NativeMessagingHosts\{HOST_NAME}"
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, firefox_sub_key) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, FIREFOX_MANIFEST_PATH)
        print(f"[SUCCESS] Registered native host for Mozilla Firefox:")
        print(f"          HKCU\\{firefox_sub_key} -> {FIREFOX_MANIFEST_PATH}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to write Firefox registry key: {e}", file=sys.stderr)
        return False


def uninstall_windows():
    """Unregister native messaging host from HKCU registry for Google Chrome and Mozilla Firefox."""
    import winreg

    chrome_sub_key = rf"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}"
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, chrome_sub_key)
        print(f"[SUCCESS] Removed Chrome HKCU\\{chrome_sub_key}")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[ERROR] Failed to delete Chrome registry key: {e}", file=sys.stderr)

    firefox_sub_key = rf"Software\Mozilla\NativeMessagingHosts\{HOST_NAME}"
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, firefox_sub_key)
        print(f"[SUCCESS] Removed Firefox HKCU\\{firefox_sub_key}")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[ERROR] Failed to delete Firefox registry key: {e}", file=sys.stderr)

    return True


def install_linux_macos(extension_ids=None):
    """Symlink or write manifest to Google Chrome native-messaging-hosts directory."""
    update_manifest_and_bat(extension_ids)
    if sys.platform == "darwin":
        target_dir = os.path.expanduser("~/Library/Application Support/Google/Chrome/NativeMessagingHosts")
    else:
        target_dir = os.path.expanduser("~/.config/google-chrome/NativeMessagingHosts")

    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, f"{HOST_NAME}.json")

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["path"] = PY_SCRIPT
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    os.chmod(PY_SCRIPT, 0o755)
    print(f"[SUCCESS] Installed manifest to: {target_path}")
    return True


def uninstall_linux_macos():
    if sys.platform == "darwin":
        target_dir = os.path.expanduser("~/Library/Application Support/Google/Chrome/NativeMessagingHosts")
    else:
        target_dir = os.path.expanduser("~/.config/google-chrome/NativeMessagingHosts")

    target_path = os.path.join(target_dir, f"{HOST_NAME}.json")
    if os.path.exists(target_path):
        os.remove(target_path)
        print(f"[SUCCESS] Removed {target_path}")
    else:
        print(f"[INFO] {target_path} not found.")
    return True


def main():
    parser = argparse.ArgumentParser(description="Install Cipher native host for Google Chrome")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall/unregister native host")
    parser.add_argument("--extension-id", action="append", dest="extension_ids",
                        help="Additional or custom Chrome Extension ID to allow")
    args = parser.parse_args()

    extension_ids = args.extension_ids or [DEFAULT_EXTENSION_ID]

    if sys.platform == "win32":
        if args.uninstall:
            success = uninstall_windows()
        else:
            success = install_windows(extension_ids)
    else:
        if args.uninstall:
            success = uninstall_linux_macos()
        else:
            success = install_linux_macos(extension_ids)

    if success and not args.uninstall:
        print("\n========================================================")
        print("Cipher Chrome Extension Setup:")
        print("1. Open Google Chrome and navigate to: chrome://extensions")
        print("2. Enable 'Developer mode' toggle in the top-right corner.")
        print("3. Click 'Load unpacked' and choose directory:")
        print(f"   {os.path.abspath(os.path.join(SCRIPT_DIR, '..'))}")
        print(f"4. Verify the extension ID matches: {DEFAULT_EXTENSION_ID}")
        print("========================================================\n")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
