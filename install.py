"""安装/卸载开机自启动（当前用户级，无需管理员权限）。

用「启动文件夹」里的快捷方式实现：登录 Windows 后自动启动守护进程（无窗口）。

用法：
    python install.py             # 安装自启动并立即启动守护进程
    python install.py --uninstall # 移除自启动并停止守护进程
    python install.py --status    # 查看当前状态
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

def _force_utf8_console() -> None:
    """让控制台按 UTF-8 解码，避免中文乱码。"""
    import ctypes
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except OSError:
            pass


_force_utf8_console()

HERE = Path(__file__).resolve().parent
LNK_NAME = "校园网自动连接.lnk"
PYTHONW = Path(sys.executable).with_name("pythonw.exe")
PYTHON = Path(sys.executable)
DAEMON = HERE / "srun_daemon.py"


def _run(args: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", **kw)


def startup_dir() -> Path:
    return Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup"


def lnk_path() -> Path:
    return startup_dir() / LNK_NAME


def _make_shortcut(target: Path, link: Path, args: str = "", workdir: Path | None = None) -> bool:
    """用 WScript.Shell 创建 .lnk（无需管理员权限）。"""
    ps = (
        "$ws = New-Object -ComObject WScript.Shell; "
        f"$s = $ws.CreateShortcut('{link}'); "
        f"$s.TargetPath = '{target}'; "
        f"$s.Arguments = '{args}'; "
        f"$s.WorkingDirectory = '{workdir or HERE}'; "
        "$s.WindowStyle = 7; "
        "$s.Description = '校园网自动认证守护进程'; "
        "$s.Save()"
    )
    r = _run(["powershell", "-NoProfile", "-Command", ps])
    return r.returncode == 0 and link.exists()


def install() -> int:
    if not DAEMON.exists():
        print(f"找不到 {DAEMON}")
        return 1
    exe = PYTHONW if PYTHONW.exists() else PYTHON
    startup_dir().mkdir(parents=True, exist_ok=True)
    if not _make_shortcut(exe, lnk_path(), f'"{DAEMON}"'):
        print("创建启动快捷方式失败")
        return 1
    print(f"已设置开机自启：{lnk_path()}")
    start_daemon()
    return 0


def start_daemon() -> None:
    exe = PYTHONW if PYTHONW.exists() else PYTHON
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
    subprocess.Popen([str(exe), str(DAEMON)], cwd=str(HERE),
                     creationflags=flags, close_fds=True,
                     stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
    print("守护进程已启动（后台无窗口）")


def _daemon_pids() -> list[str]:
    ps = (
        "Get-CimInstance Win32_Process -Filter \"Name='pythonw.exe' or Name='python.exe'\" | "
        f"Where-Object {{ $_.CommandLine -like '*{DAEMON.name}*' }} | "
        "Select-Object -ExpandProperty ProcessId"
    )
    r = _run(["powershell", "-NoProfile", "-Command", ps])
    return [p for p in (r.stdout or "").split() if p.strip().isdigit()]


def stop_daemon() -> None:
    pids = _daemon_pids()
    for pid in pids:
        _run(["taskkill", "/F", "/PID", pid])
    if pids:
        print(f"守护进程已停止（PID {', '.join(pids)}）")
    else:
        print("守护进程未在运行")


def status() -> int:
    print("开机自启：", "已设置" if lnk_path().exists() else "未设置")
    pids = _daemon_pids()
    print("守护进程：", f"运行中 (PID {', '.join(pids)})" if pids else "未运行")

    sys.path.insert(0, str(HERE))
    import srun_core as S
    creds = S.load_credentials()
    print("凭据：", f"已保存（{creds[0]}）" if creds else "未配置，请运行 setup.cmd")
    print("门户在线：", "是" if S.online_info() else "否")
    print("外网：", "可达" if S.internet_ok() else "不可达")
    print(f"日志：{S.LOG_FILE}")
    return 0


def uninstall() -> int:
    if lnk_path().exists():
        lnk_path().unlink()
        print("已移除开机自启")
    else:
        print("开机自启未设置")
    stop_daemon()
    return 0


def main(argv: list[str]) -> int:
    if "--uninstall" in argv:
        return uninstall()
    if "--status" in argv:
        return status()
    return install()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
