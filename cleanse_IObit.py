#!/usr/bin/env python3
# cleanup_win_embedded.py
# Purpose: Use hardcoded arrays to scan folders for files and delete them, and remove specified Windows registry keys.
# Communication is via terminal output with verbosity control. Suitable for freezing to an EXE on Windows.

import ctypes
import fnmatch
import logging
import os
import sys
import glob
import shutil
import tempfile
from pathlib import Path

# --- Windows registry support ---
try:
    import winreg  # Windows only
    ON_WINDOWS = True
except ImportError:
    winreg = None
    ON_WINDOWS = False

# ===========================
# CONFIGURATION (EDIT THESE)
# ===========================
FILES_TO_SCAN = [
    r"%All Users Profile%\IObit\IObitRtt\IURtt.ept",
    r"%AppDataLocalLow%\IObit\AUpdate.ini",
    r"%Application Data%\IObit\IObit Uninstaller\BCleanerdb",
    r"%Application Data%\IObit\IObit Uninstaller\BCleanerdb-journal",
    r"%Application Data%\IObit\IObit Uninstaller\DistrustPlugin.ini",
    r"%Application Data%\IObit\IObit Uninstaller\Log\2025-04-14.dbg",
    r"%Application Data%\IObit\IObit Uninstaller\Main.ini",
    r"%Application Data%\IObit\IObit Uninstaller\PluginCache.ini",
    r"%Application Data%\IObit\IObit Uninstaller\SHCatch.ini",
    r"%Application Data%\IObit\IObit Uninstaller\SoftwareCache.ini",
    r"%Application Data%\IObit\IObit Uninstaller\SoftwareHealth.ini",
    r"%Application Data%\IObit\IObit Uninstaller\UninstallHistory.ini",
    r"%Application Data%\IObit\PPMain.ini",
    r"%Temporary Internet Files%\Content.IE5\7KZJEKTK\active_month[1].php",
    r"%User Temp%\{random}.tmp",
    r"%User Temp%\IObitUninstaller\!)清理残留.bat",
    r"%User Temp%\IObitUninstaller\Action Center\itop.png",
    r"%User Temp%\IObitUninstaller\AUpdate.exe",
    r"%User Temp%\IObitUninstaller\Database\AppRate.dbd",
    r"%User Temp%\IObitUninstaller\Database\FB.dbd",
    r"%User Temp%\IObitUninstaller\Database\PlugDB.dbd",
    r"%User Temp%\IObitUninstaller\Database\PSExt.dbd",
    r"%User Temp%\IObitUninstaller\Database\SBData.dbd",
    r"%User Temp%\IObitUninstaller\Database\sMarUpdateInfo.dbd",
    r"%User Temp%\IObitUninstaller\Database\SoftHealth.dbd",
    r"%User Temp%\IObitUninstaller\Database\SoftPM.dbd",
    r"%User Temp%\IObitUninstaller\Database\sUpdate.dbd",
    r"%User Temp%\IObitUninstaller\Database\uninstall_qdb.dbd",
    r"%User Temp%\IObitUninstaller\Database\UninstallRote.dbd",
    r"%User Temp%\IObitUninstaller\Database\usoft.dbd",
    r"%User Temp%\IObitUninstaller\datastate.dll",
    r"%User Temp%\IObitUninstaller\Drivers\win10_amd64\IUFileFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win10_amd64\IUForceDelete.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win10_amd64\IUProcessFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win10_amd64\IURegistryFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win10_ia64\IUFileFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win10_ia64\IUForceDelete.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win10_ia64\IUProcessFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win10_ia64\IURegistryFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win10_x86\IUFileFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win10_x86\IUForceDelete.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win10_x86\IUProcessFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win10_x86\IURegistryFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win7_amd64\IUFileFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win7_amd64\IUForceDelete.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win7_amd64\IUProcessFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win7_amd64\IURegistryFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win7_ia64\IUFileFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win7_ia64\IUForceDelete.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win7_ia64\IUProcessFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win7_ia64\IURegistryFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win7_x86\IUFileFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win7_x86\IUForceDelete.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win7_x86\IUProcessFilter.sys",
    r"%User Temp%\IObitUninstaller\Drivers\win7_x86\IURegistryFilter.sys",
    r"%User Temp%\IObitUninstaller\DS\DSConfig.ini",
    r"%User Temp%\IObitUninstaller\DS\DSNow.data",
    r"%User Temp%\IObitUninstaller\DSPut.exe",
    r"%User Temp%\IObitUninstaller\filectl.dll",
    r"%User Temp%\IObitUninstaller\forcedelctl.dll",
    r"%User Temp%\IObitUninstaller\InfoHelp.dll",
    r"%User Temp%\IObitUninstaller\IObitUninstaler.exe",
    r"%User Temp%\IObitUninstaller\iush.exe",
    r"%User Temp%\IObitUninstaller\lang.dat",
    r"%User Temp%\IObitUninstaller\Language\English.lng",
    r"%User Temp%\IObitUninstaller\LatestNews",
    r"%User Temp%\IObitUninstaller\libcrypto-1_1.dll",
    r"%User Temp%\IObitUninstaller\libssl-1_1.dll",
    r"%User Temp%\IObitUninstaller\madbasic_.bpl",
    r"%User Temp%\IObitUninstaller\maddisAsm_.bpl",
    r"%User Temp%\IObitUninstaller\madexcept_.bpl",
    r"%User Temp%\IObitUninstaller\Main.ini",
    r"%User Temp%\IObitUninstaller\NoteIcon.exe",
    r"%User Temp%\IObitUninstaller\PluginHelper.dll",
    r"%User Temp%\IObitUninstaller\PPUninstaller.exe",
    r"%User Temp%\IObitUninstaller\ProductNews2.dll",
    r"%User Temp%\IObitUninstaller\RegisterCom.dll",
    r"%User Temp%\IObitUninstaller\rgfpctl.dll",
    r"%User Temp%\IObitUninstaller\rtl120.bpl",
    r"%User Temp%\IObitUninstaller\Skin\classic.dll",
    r"%User Temp%\IObitUninstaller\Skin\public.dll",
    r"%User Temp%\IObitUninstaller\Skin\white.dll",
    r"%User Temp%\IObitUninstaller\SpecUTool.exe",
    r"%User Temp%\IObitUninstaller\sqlite3.dll",
    r"%User Temp%\IObitUninstaller\SysRest.dll",
    r"%User Temp%\IObitUninstaller\update",
    r"%User Temp%\IObitUninstaller\vcl120.bpl",
    r"%User Temp%\IObitUninstaller\vclx120.bpl",
    r"%User Temp%\IObitUninstaller\webres.dll",
    r"%User Temp%\IObitUninstaller\winid.dat",
    r"%User Temp%\SoftHealth.dbd",
    r"%User Temp%\sUpdate.dbd",
    r"%User Temp%\usoft.dbd",
]

FOLDERS_TO_SCAN = [
    r"%All Users Profile%\IObit",
    r"%All Users Profile%\IObit\IObit Uninstaller",
    r"%All Users Profile%\IObit\IObit Uninstaller\Downloader",
    r"%All Users Profile%\IObit\IObitRtt",
    r"%AppDataLocalLow%\IObit",
    r"%Application Data%\IObit\IObit Uninstaller",
    r"%Application Data%\IObit\IObit Uninstaller\Log",
    r"%Program Files%\COMMON FILES\IObit",
    r"%Program Files%\COMMON FILES\IObit\IObit Uninstaller",
    r"%User Temp%\AUpdate.madExcept",
    r"%User Temp%\DSPut.madExcept",
    r"%User Temp%\IObitUninstaler.madExcept",
    r"%User Temp%\IObitUninstaller",
    r"%User Temp%\IObitUninstaller\Action Center",
    r"%User Temp%\IObitUninstaller\Database",
    r"%User Temp%\IObitUninstaller\Drivers",
    r"%User Temp%\IObitUninstaller\Drivers\win10_amd64",
    r"%User Temp%\IObitUninstaller\Drivers\win10_ia64",
    r"%User Temp%\IObitUninstaller\Drivers\win10_x86",
    r"%User Temp%\IObitUninstaller\Drivers\win7_amd64",
    r"%User Temp%\IObitUninstaller\Drivers\win7_ia64",
    r"%User Temp%\IObitUninstaller\Drivers\win7_x86",
    r"%User Temp%\IObitUninstaller\DS",
    r"%User Temp%\IObitUninstaller\Language",
    r"%User Temp%\IObitUninstaller\Skin",
    r"%User Temp%\PPUninstaller.madExcept"
]

FILE_PATTERNS = []  # it will match all files

REGISTRY_KEYS_TO_DELETE = [
    r"HKEY_LOCAL_MACHINE\SOFTWARE\IObit"
]

# Registry view control
REGISTRY_VIEW = "auto"  # "auto" | "64" | "32" | "both"

# Behavior flags
DRY_RUN = False              # True = show what would be deleted; False = actually delete
REMOVE_EMPTY_DIRS = True     # Remove empty directories after deleting files in FOLDERS_TO_SCAN
NON_ADMIN_OK = False         # Proceed without admin (best effort). Consider True only when you're sure.

# Logging verbosity: 0=errors only, 1=info (default), 2=debug
VERBOSITY = 1

# Keep the console window open after the program finishes (useful when double-clicking the EXE)
PAUSE_ON_EXIT = True

# ===========================
# END CONFIGURATION
# ===========================

# ---------------------------
# Logging / Verbosity
# ---------------------------
def setup_logging(verbosity: int):
    level = logging.ERROR if verbosity == 0 else (logging.INFO if verbosity == 1 else logging.DEBUG)
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )

# ---------------------------
# Admin (UAC) Check
# ---------------------------
def is_admin() -> bool:
    if not ON_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

# ---------------------------
# Special token expansion
# ---------------------------
# CSIDL constants
CSIDL_APPDATA = 0x001a
CSIDL_INTERNET_CACHE = 0x0020

def _sh_get_folder_path(csidl: int) -> str:
    """Resolve legacy CSIDL paths via SHGetFolderPathW."""
    buf = ctypes.create_unicode_buffer(260)
    res = ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buf)
    if res != 0:
        raise OSError(f"SHGetFolderPathW failed for CSIDL {csidl} (code={res})")
    return buf.value

def _resolve_special_token(token: str) -> str:
    token_upper = token.strip().lower()
    if token_upper == "%application data%":
        try:
            return _sh_get_folder_path(CSIDL_APPDATA)
        except Exception:
            # Fallback to %APPDATA%
            return os.environ.get("APPDATA", "")
    if token_upper == "%user temp%":
        return os.environ.get("TEMP", tempfile.gettempdir())
    if token_upper == "%temporary internet files%":
        try:
            return _sh_get_folder_path(CSIDL_INTERNET_CACHE)
        except Exception:
            # Typical fallback
            return os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "INetCache")
    # NEW: support tokens used in your arrays
    if token_upper == "%all users profile%":
        # Typically C:\ProgramData
        return os.environ.get("ALLUSERSPROFILE", os.environ.get("PROGRAMDATA", ""))
    if token_upper == "%appdatalocallow%":
        # Typically %LOCALAPPDATA%\Low or %USERPROFILE%\AppData\LocalLow
        base = os.environ.get("LOCALAPPDATA", "")
        locallow = os.path.join(base, "Low") if base else ""
        return locallow if locallow else os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "LocalLow")
    return token  # unchanged

def expand_special_tokens(path_str: str) -> str:
    """
    Replace our custom tokens and expand normal %ENVVARS%.
    Supports tokens embedded anywhere in the path.
    """
    for tok in ["%Application Data%", "%User Temp%", "%Temporary Internet Files%", "%All Users Profile%", "%AppDataLocalLow%"]:
        if tok.lower() in path_str.lower():
            resolved = _resolve_special_token(tok)
            if resolved:
                # Case-insensitive replace (simple form)
                path_str = path_str.replace(tok, resolved)
                path_str = path_str.replace(tok.lower(), resolved)
    # Expand remaining standard environment variables
    path_str = os.path.expandvars(path_str)
    # Normalize any forward slashes just in case
    path_str = path_str.replace("/", "\\")
    return path_str

# ---------------------------
# File Deletion (Folder scan)
# ---------------------------
def make_writable(path: Path):
    try:
        if not path.exists():
            return
        mode = path.stat().st_mode
        path.chmod(mode | 0o200)  # add write bit
    except Exception as e:
        logging.debug(f"[Files] Could not change mode for {path}: {e}")

def delete_files_in_folders(folders, patterns, dry_run=False, remove_empty_dirs=False):
    if not patterns:
        patterns = ["*"]  # default to all files if not specified

    total_found = 0
    total_deleted = 0

    for folder in folders:
        # IMPORTANT: expand the same special tokens here
        expanded_folder = expand_special_tokens(folder)
        base = Path(expanded_folder).expanduser()
        if not base.exists() or not base.is_dir():
            logging.info(f"[Files] Folder not found or not a directory: {base}")
            continue

        logging.info(f"[Files] Scanning: {base}")
        for root, dirs, files in os.walk(base):
            root_path = Path(root)
            for pattern in patterns:
                for name in fnmatch.filter(files, pattern):
                    file_path = root_path / name
                    total_found += 1
                    if dry_run:
                        logging.info(f"[Files] (dry-run) Would delete file: {file_path}")
                        continue
                    try:
                        make_writable(file_path)
                        file_path.unlink(missing_ok=True)
                        logging.info(f"[Files] Deleted file: {file_path}")
                        total_deleted += 1
                    except PermissionError as e:
                        logging.error(f"[Files] Permission denied deleting {file_path}: {e}")
                    except Exception as e:
                        logging.error(f"[Files] Error deleting {file_path}: {e}")

        if remove_empty_dirs and not dry_run:
            for root, dirs, files in os.walk(base, topdown=False):
                root_path = Path(root)
                try:
                    if not any(Path(root).iterdir()):
                        root_path.rmdir()
                        logging.info(f"[Files] Removed empty directory: {root_path}")
                except Exception as e:
                    logging.debug(f"[Files] Could not remove directory {root_path}: {e}")

    if total_found == 0:
        logging.info("[Files] No matching files found for the given patterns.")
    else:
        logging.info(f"[Files] Found: {total_found} | Deleted: {total_deleted} | "
                     f"{'(dry-run)' if dry_run else ''}")

# ---------------------------
# Specific Paths Deletion
# ---------------------------
def delete_specific_paths(paths, dry_run=False):
    """
    Delete specific paths (files or directories). Supports:
      - Special tokens (%Application Data%, %User Temp%, %Temporary Internet Files%, %All Users Profile%, %AppDataLocalLow%)
      - Environment variables
      - {random} -> * wildcard expansion
      - Recursive deletion for directories
      - Globbing only when wildcards are present
    """
    if not paths:
        logging.info("[Paths] No specific paths provided; skipping.")
        return

    for original in paths:
        # {random} wildcard expansion
        candidate = original.replace("{random}", "*")

        # Expand tokens and env vars
        expanded = expand_special_tokens(candidate)

        # Glob when wildcards are present
        use_glob = any(ch in expanded for ch in ["*", "?"])
        matches = []
        if use_glob:
            matches = glob.glob(expanded)
            if not matches:
                logging.info(f"[Paths] Not found (pattern): {expanded}")
                continue
        else:
            matches = [expanded] if os.path.exists(expanded) else []
            if not matches:
                logging.info(f"[Paths] Not found: {expanded}")
                continue

        for match in matches:
            p = Path(match)
            try:
                if p.is_dir():
                    if dry_run:
                        logging.info(f"[Paths] (dry-run) Would remove directory (tree): {p}")
                    else:
                        shutil.rmtree(p, ignore_errors=False)
                        logging.info(f"[Paths] Removed directory (tree): {p}")
                else:
                    if dry_run:
                        logging.info(f"[Paths] (dry-run) Would delete file: {p}")
                    else:
                        make_writable(p)
                        p.unlink(missing_ok=True)
                        logging.info(f"[Paths] Deleted file: {p}")
            except PermissionError as e:
                logging.error(f"[Paths] Permission denied removing {p}: {e}")
            except FileNotFoundError:
                logging.info(f"[Paths] Already removed or not found: {p}")
            except Exception as e:
                logging.error(f"[Paths] Error removing {p}: {e}")

# ---------------------------
# Registry Helpers
# ---------------------------
_HIVE_MAP = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKEY_USERS": "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
    "HKEY_CURRENT_CONFIG": "HKEY_CURRENT_CONFIG",
}

_HIVE_CONST = {
    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE if ON_WINDOWS else None,
    "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER if ON_WINDOWS else None,
    "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT if ON_WINDOWS else None,
    "HKEY_USERS": winreg.HKEY_USERS if ON_WINDOWS else None,
    "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG if ON_WINDOWS else None,
}

def _launched_by_double_click() -> bool:
    """
    Returns True if the process appears to be the only one attached to the console,
    which usually means it was launched by double-click (Windows created a new console for it).
    """
    if not ON_WINDOWS:
        return False
    try:
        GetConsoleProcessList = getattr(ctypes.windll.kernel32, "GetConsoleProcessList", None)
        if not GetConsoleProcessList:
            return False
        arr = (ctypes.c_ulong * 1)()
        count = GetConsoleProcessList(arr, 1)
        # If only our process is attached, likely a fresh console from double-click.
        return count <= 1
    except Exception:
        return False

def pause_at_end():
    """Pause the console so it doesn't close immediately after the program finishes."""
    if not ON_WINDOWS or not PAUSE_ON_EXIT:
        return
    try:
        if _launched_by_double_click():
            # Native Windows pause prompt
            os.system("pause")
            return
        # Fallback: if we're attached to a TTY, prompt to exit
        if sys.stdin and sys.stdin.isatty():
            input("\nPress Enter to exit...")
    except Exception:
        # Never let the pause logic crash the program on exit
        pass


def parse_registry_path(path_str: str):
    if not ON_WINDOWS:
        raise EnvironmentError("Registry operations require Windows.")
    p = path_str.strip().replace("/", "\\")
    if "\\" not in p:
        raise ValueError(f"Invalid registry path (missing hive): {path_str}")
    hive_name, subkey = p.split("\\", 1)
    hive_full = _HIVE_MAP.get(hive_name.upper())
    if not hive_full:
        raise ValueError(f"Unsupported hive in path: {path_str}")
    hive_const = _HIVE_CONST.get(hive_full)
    if hive_const is None:
        raise ValueError(f"Hive mapping failed: {hive_full}")
    return hive_const, subkey

def _open_key_for_delete(hive, subkey, view: str):
    access = winreg.KEY_READ | winreg.KEY_WRITE | winreg.KEY_ENUMERATE_SUB_KEYS
    if view == "64":
        access |= winreg.KEY_WOW64_64KEY
    elif view == "32":
        access |= winreg.KEY_WOW64_32KEY
    return winreg.OpenKey(hive, subkey, 0, access)

def _delete_key_ex(hive, subkey, view: str):
    access_flags = winreg.KEY_WRITE
    if view == "64":
        access_flags |= winreg.KEY_WOW64_64KEY
    elif view == "32":
        access_flags |= winreg.KEY_WOW64_32KEY
    if hasattr(winreg, "DeleteKeyEx"):
        try:
            winreg.DeleteKeyEx(hive, subkey, access_flags, 0)
            return True
        except FileNotFoundError:
            return False
        except PermissionError as e:
            logging.error(f"[Registry] Permission denied deleting key {subkey}: {e}")
            return False
        except OSError as e:
            logging.debug(f"[Registry] DeleteKeyEx failed for {subkey}: {e}")
    try:
        winreg.DeleteKey(hive, subkey)
        return True
    except FileNotFoundError:
        return False
    except PermissionError as e:
        logging.error(f"[Registry] Permission denied deleting key {subkey}: {e}")
        return False
    except OSError as e:
        logging.debug(f"[Registry] DeleteKey failed for {subkey}: {e}")
        return False

def delete_registry_tree(full_path: str, view: str = "auto", dry_run: bool = False) -> bool:
    hive, subkey = parse_registry_path(full_path)
    try:
        key = _open_key_for_delete(hive, subkey, view)
    except FileNotFoundError:
        logging.info(f"[Registry] Key not found: {full_path} ({view}-view)")
        return False
    except PermissionError as e:
        logging.error(f"[Registry] Permission denied opening {full_path}: {e}")
        return False

    try:
        while True:
            try:
                child_name = winreg.EnumKey(key, 0)
            except OSError:
                break
            child_full = f"{full_path}\\{child_name}"
            if dry_run:
                logging.info(f"[Registry] (dry-run) Would delete key (tree): {child_full} ({view}-view)")
                delete_registry_tree(child_full, view=view, dry_run=True)
            else:
                winreg.CloseKey(key)
                delete_registry_tree(child_full, view=view, dry_run=False)
                key = _open_key_for_delete(hive, subkey, view)
    finally:
        try:
            winreg.CloseKey(key)
        except Exception:
            pass

    if dry_run:
        logging.info(f"[Registry] (dry-run) Would delete key: {full_path} ({view}-view)")
        return True

    deleted = _delete_key_ex(hive, subkey, view)
    if deleted:
        logging.info(f"[Registry] Deleted key: {full_path} ({view}-view)")
        return True
    else:
        try:
            _ = _open_key_for_delete(hive, subkey, view)
            logging.error(f"[Registry] Failed to delete key (still exists): {full_path} ({view}-view)")
            return False
        except FileNotFoundError:
            logging.info(f"[Registry] Key already removed: {full_path} ({view}-view)")
            return True
        except Exception:
            return False

def delete_registry_keys(keys, view: str, dry_run: bool):
    if not keys:
        logging.info("[Registry] No registry keys specified; skipping registry cleanup.")
        return
    views_to_try = ["64", "32"] if view == "both" else [view]
    for key_path in keys:
        for eff_view in views_to_try:
            try:
                delete_registry_tree(key_path, view=eff_view, dry_run=dry_run)
            except ValueError as e:
                logging.error(f"[Registry] Invalid path '{key_path}': {e}")
            except EnvironmentError as e:
                logging.error(f"[Registry] Environment error for '{key_path}': {e}")
            except Exception as e:
                logging.error(f"[Registry] Unexpected error for '{key_path}': {e}")

# ---------------------------
# Main
# ---------------------------
def main():
    setup_logging(VERBOSITY)

    if not ON_WINDOWS:
        logging.error("This program is intended for Windows systems (winreg is required).")
        return 2

    if not is_admin() and not NON_ADMIN_OK and not DRY_RUN:
        logging.error(
            "Administrator privileges are recommended for registry and protected folders.\n"
            "Run this program as Administrator, or set NON_ADMIN_OK=True for best-effort, "
            "or use DRY_RUN=True to preview."
        )
        return 3

    # File cleanup (pattern-based)
    if FOLDERS_TO_SCAN:
        logging.info("===== FILE CLEANUP (patterns) =====")
        delete_files_in_folders(
            folders=FOLDERS_TO_SCAN,
            patterns=FILE_PATTERNS,
            dry_run=DRY_RUN,
            remove_empty_dirs=REMOVE_EMPTY_DIRS,
        )
    else:
        logging.info("[Files] No folders specified; skipping pattern-based cleanup.")

    # Specific path cleanup
    if FILES_TO_SCAN:
        logging.info("===== SPECIFIC PATHS CLEANUP =====")
        delete_specific_paths(FILES_TO_SCAN, dry_run=DRY_RUN)
    else:
        logging.info("[Paths] No specific paths configured; skipping.")

    # Registry cleanup
    if REGISTRY_KEYS_TO_DELETE:
        logging.info("===== REGISTRY CLEANUP =====")
        if REGISTRY_VIEW not in ("auto", "32", "64", "both"):
            logging.error(f"[Registry] Invalid REGISTRY_VIEW: {REGISTRY_VIEW}")
        else:
            delete_registry_keys(REGISTRY_KEYS_TO_DELETE, view=REGISTRY_VIEW, dry_run=DRY_RUN)
    else:
        logging.info("[Registry] No registry keys specified; skipping registry cleanup.")

    logging.info("Done.")
    return 0

if __name__ == "__main__":
    exit_code = main()
    try:
        pause_at_end()
    finally:
        sys.exit(exit_code)