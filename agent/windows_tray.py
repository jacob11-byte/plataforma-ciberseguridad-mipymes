from __future__ import annotations

import argparse
import ctypes
import os
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.outbox import default_data_root
from agent.public_status import read_public_status


# PyInstaller stores the icon passed with --icon as resource 1 in the
# executable. Keep the Windows shield only as a defensive fallback for old or
# manually-built binaries that do not contain the CyberCheck resource.
APPLICATION_ICON_RESOURCE_ID = 1
FALLBACK_ICON_RESOURCE_ID = 32518


def status_summary(status: dict[str, Any]) -> str:
    service = status.get("service_state", "unknown")
    connectivity = status.get("connectivity", "unknown")
    pending = int(status.get("outbox_pending") or 0)
    labels = {
        ("running", "online"): "Proteccion activa y conectada",
        ("running", "offline"): "Proteccion activa, servidor sin conexion",
        ("running", "revoked"): "Equipo desconectado desde el panel",
        ("starting", "unknown"): "Servicio iniciando",
        ("stopped", "online"): "Servicio detenido",
        ("failed", "unknown"): "Servicio con error",
        ("blocked", "unknown"): "Servicio bloqueado por otra instancia",
    }
    summary = labels.get((service, connectivity), f"Servicio: {service}; conexion: {connectivity}")
    if pending:
        summary += f"; {pending} resultado(s) en cola"
    return summary


class WindowsTray:
    def __init__(self, data_root: Path) -> None:
        if os.name != "nt":
            raise RuntimeError("La aplicacion de bandeja solo funciona en Windows")
        from ctypes import wintypes

        self.wintypes = wintypes
        self.data_root = data_root
        self.hwnd: int | None = None
        self.icon_data: Any = None
        self.class_name = "CyberCheckTrayWindow"
        self.wm_tray = 0x8000 + 41
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure_types()

    def _configure_types(self) -> None:
        wt = self.wintypes
        self.wndproc_type = ctypes.WINFUNCTYPE(
            ctypes.c_ssize_t, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM
        )

        class WindowClass(ctypes.Structure):
            _fields_ = [
                ("style", wt.UINT),
                ("lpfnWndProc", self.wndproc_type),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wt.HINSTANCE),
                ("hIcon", wt.HICON),
                ("hCursor", wt.HANDLE),
                ("hbrBackground", wt.HBRUSH),
                ("lpszMenuName", wt.LPCWSTR),
                ("lpszClassName", wt.LPCWSTR),
            ]

        class NotifyIconData(ctypes.Structure):
            _fields_ = [
                ("cbSize", wt.DWORD),
                ("hWnd", wt.HWND),
                ("uID", wt.UINT),
                ("uFlags", wt.UINT),
                ("uCallbackMessage", wt.UINT),
                ("hIcon", wt.HICON),
                ("szTip", wt.WCHAR * 128),
                ("dwState", wt.DWORD),
                ("dwStateMask", wt.DWORD),
                ("szInfo", wt.WCHAR * 256),
                ("uTimeoutOrVersion", wt.UINT),
                ("szInfoTitle", wt.WCHAR * 64),
                ("dwInfoFlags", wt.DWORD),
                ("guidItem", ctypes.c_byte * 16),
                ("hBalloonIcon", wt.HICON),
            ]

        self.WindowClass = WindowClass
        self.NotifyIconData = NotifyIconData
        # Handles and LPARAM values exceed 32 bits on x64; without explicit
        # argtypes ctypes would pass them as C int and raise ArgumentError.
        user32, shell32, kernel32 = self.user32, self.shell32, self.kernel32
        user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
        user32.DefWindowProcW.restype = ctypes.c_ssize_t
        user32.RegisterClassW.argtypes = [ctypes.POINTER(WindowClass)]
        user32.RegisterClassW.restype = wt.ATOM
        user32.CreateWindowExW.argtypes = [
            wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, ctypes.c_int, ctypes.c_int,
            ctypes.c_int, ctypes.c_int, wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID,
        ]
        user32.CreateWindowExW.restype = wt.HWND
        user32.DestroyWindow.argtypes = [wt.HWND]
        user32.LoadIconW.argtypes = [wt.HINSTANCE, wt.LPCWSTR]
        user32.LoadIconW.restype = wt.HICON
        user32.CreatePopupMenu.restype = wt.HMENU
        user32.AppendMenuW.argtypes = [wt.HMENU, wt.UINT, ctypes.c_size_t, wt.LPCWSTR]
        user32.DestroyMenu.argtypes = [wt.HMENU]
        user32.SetForegroundWindow.argtypes = [wt.HWND]
        user32.TrackPopupMenu.argtypes = [
            wt.HMENU, wt.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.HWND, wt.LPVOID,
        ]
        user32.SetTimer.argtypes = [wt.HWND, ctypes.c_size_t, wt.UINT, wt.LPVOID]
        user32.SetTimer.restype = ctypes.c_size_t
        user32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wt.MSG)]
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wt.MSG)]
        user32.DispatchMessageW.restype = ctypes.c_ssize_t
        shell32.Shell_NotifyIconW.argtypes = [wt.DWORD, ctypes.POINTER(NotifyIconData)]
        shell32.Shell_NotifyIconW.restype = wt.BOOL
        kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wt.HMODULE

    def _tooltip(self) -> str:
        return ("CyberCheck - " + status_summary(read_public_status(self.data_root)))[:127]

    def _load_application_icon(self, instance: int) -> int:
        resource = ctypes.cast(ctypes.c_void_p(APPLICATION_ICON_RESOURCE_ID), self.wintypes.LPCWSTR)
        icon = self.user32.LoadIconW(instance, resource)
        if icon:
            return icon
        fallback = ctypes.cast(ctypes.c_void_p(FALLBACK_ICON_RESOURCE_ID), self.wintypes.LPCWSTR)
        return self.user32.LoadIconW(None, fallback)

    def _update_icon(self, add: bool = False) -> None:
        if not self.icon_data:
            return
        self.icon_data.szTip = self._tooltip()
        self.shell32.Shell_NotifyIconW(0 if add else 1, ctypes.byref(self.icon_data))

    def _open_dashboard(self) -> None:
        status = read_public_status(self.data_root)
        url = status.get("dashboard_url")
        if isinstance(url, str) and url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            os.startfile(url)  # type: ignore[attr-defined]

    def _show_menu(self) -> None:
        wt = self.wintypes

        class Point(ctypes.Structure):
            _fields_ = [("x", wt.LONG), ("y", wt.LONG)]

        menu = self.user32.CreatePopupMenu()
        summary = status_summary(read_public_status(self.data_root))[:90]
        self.user32.AppendMenuW(menu, 0x00000001, 0, summary)
        self.user32.AppendMenuW(menu, 0x00000800, 0, None)
        self.user32.AppendMenuW(menu, 0, 1001, "Abrir panel")
        self.user32.AppendMenuW(menu, 0, 1002, "Actualizar estado")
        self.user32.AppendMenuW(menu, 0, 1003, "Cerrar icono")
        point = Point()
        self.user32.GetCursorPos(ctypes.byref(point))
        self.user32.SetForegroundWindow(self.hwnd)
        command = self.user32.TrackPopupMenu(
            menu, 0x0100 | 0x0002, point.x, point.y, 0, self.hwnd, None
        )
        self.user32.DestroyMenu(menu)
        if command == 1001:
            self._open_dashboard()
        elif command == 1002:
            self._update_icon()
        elif command == 1003:
            self.user32.DestroyWindow(self.hwnd)

    def run(self) -> int:
        wt = self.wintypes
        wm_destroy = 0x0002
        wm_timer = 0x0113
        wm_lbutton_dblclk = 0x0203
        wm_rbutton_up = 0x0205

        @self.wndproc_type
        def wndproc(hwnd: int, message: int, wparam: int, lparam: int) -> int:
            if message == self.wm_tray:
                if lparam == wm_lbutton_dblclk:
                    self._open_dashboard()
                elif lparam == wm_rbutton_up:
                    self._show_menu()
                return 0
            if message == wm_timer:
                self._update_icon()
                return 0
            if message == wm_destroy:
                if self.icon_data:
                    self.shell32.Shell_NotifyIconW(2, ctypes.byref(self.icon_data))
                self.user32.PostQuitMessage(0)
                return 0
            return self.user32.DefWindowProcW(hwnd, message, wparam, lparam)

        self._wndproc = wndproc
        instance = self.kernel32.GetModuleHandleW(None)
        window_class = self.WindowClass()
        window_class.lpfnWndProc = wndproc
        window_class.hInstance = instance
        window_class.hIcon = self._load_application_icon(instance)
        window_class.lpszClassName = self.class_name
        atom = self.user32.RegisterClassW(ctypes.byref(window_class))
        if not atom and ctypes.get_last_error() != 1410:
            raise OSError(ctypes.get_last_error(), "No se pudo registrar la ventana de bandeja")
        self.hwnd = self.user32.CreateWindowExW(
            0, self.class_name, "CyberCheck", 0, 0, 0, 0, 0, None, None, instance, None
        )
        if not self.hwnd:
            raise OSError(ctypes.get_last_error(), "No se pudo crear la ventana de bandeja")
        self.icon_data = self.NotifyIconData()
        self.icon_data.cbSize = ctypes.sizeof(self.NotifyIconData)
        self.icon_data.hWnd = self.hwnd
        self.icon_data.uID = 1
        self.icon_data.uFlags = 0x00000001 | 0x00000002 | 0x00000004
        self.icon_data.uCallbackMessage = self.wm_tray
        self.icon_data.hIcon = window_class.hIcon
        self.icon_data.szTip = self._tooltip()
        self._update_icon(add=True)
        self.user32.SetTimer(self.hwnd, 1, 30_000, None)
        message = wt.MSG()
        while self.user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
            self.user32.TranslateMessage(ctypes.byref(message))
            self.user32.DispatchMessageW(ctypes.byref(message))
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="CyberCheck MIPYME - estado en bandeja")
    parser.add_argument("--data-root", default=str(default_data_root()))
    args = parser.parse_args()
    if os.name != "nt":
        return 1
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    mutex = kernel32.CreateMutexW(None, False, "Local\\CyberCheckTray")
    if not mutex or ctypes.get_last_error() == 183:
        return 0
    try:
        return WindowsTray(Path(args.data_root)).run()
    finally:
        kernel32.CloseHandle(mutex)


if __name__ == "__main__":
    raise SystemExit(main())
