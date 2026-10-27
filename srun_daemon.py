"""校园网自动认证守护进程。

触发策略（两条腿，都不需要管理员权限）：
  1. 轻量轮询（默认 5 秒）：只看"有没有可用的 IPv4 地址"，开销极小；
  2. 联网探测（默认 30 秒）：确认真能访问外网，不通就尝试认证。

之所以不用 NotifyAddrChange 事件：该 API 的 OVERLAPPED 语义在 Python 里
不可靠（实测始终超时），而轮询一个 UDP connect 只需微秒级开销，且能覆盖
插网线、Wi-Fi 重连、休眠唤醒、认证掉线全部场景。

运行：
    python srun_daemon.py            # 前台运行（调试用）
    python srun_daemon.py --once     # 只检测+认证一次就退出
    pythonw srun_daemon.py           # 无窗口后台运行（自启动用）

单实例：命名互斥体防止重复启动。
"""
from __future__ import annotations

import ctypes
import signal
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import srun_core as S  # noqa: E402

MUTEX_NAME = "Global\\SrunAutoDaemon_uestc"

LINK_POLL = 1           # 链路轮询间隔（秒）——UDP connect，约 0.12ms，零流量
SESSION_POLL = 2        # 门户会话查询间隔（秒）——走局域网，不消耗外网流量
EXTERNAL_POLL = 60      # 外网实测间隔（秒）——真实流量，仅作兜底校验
FAIL_BACKOFF_MAX = 300  # 连续失败最大退避（秒）
SETTLE_AFTER_LINK = 1   # 链路刚出现后等 DHCP 的初始等待（秒）

# ---------------------------------------------------------------- 单实例


def acquire_single_instance():
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateMutexW(None, True, MUTEX_NAME)
    if not handle:
        return None
    if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        kernel32.CloseHandle(handle)
        return None
    return handle


# ---------------------------------------------------------------- 链路探测


def default_source_ip(target: tuple[str, int] = ("223.5.5.5", 53)) -> str | None:
    """取通往该目标时使用的源 IP；无路由返回 None。不产生任何流量。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    try:
        s.connect(target)
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    if not ip or ip.startswith("127.") or ip.startswith("169.254."):
        return None
    return ip


def has_link() -> bool:
    """本机是否有可用的 IPv4 出口（插了网线/连了 Wi-Fi）。"""
    return default_source_ip() is not None


def portal_source_ip() -> str | None:
    """通往校园网门户所用的源 IP；门户不可达时返回 None。"""
    return default_source_ip((S.PORTAL_HOST, 80))


def wait_for_link(timeout: float) -> bool:
    """在 timeout 内等待拿到 IPv4 地址，拿到就立刻返回。

    替代固定 sleep：DHCP 通常 1-2 秒完成，没必要盲等固定秒数。
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if has_link():
            return True
        time.sleep(0.2)
    return has_link()


# ---------------------------------------------------------------- 认证动作


def _cred_mtime() -> float:
    """cred.bin 的修改时间；不存在返回 0。用于检测用户重新设置了密码。"""
    try:
        return S.CRED_FILE.stat().st_mtime
    except OSError:
        return 0.0


def _is_password_error(reason: str) -> bool:
    """服务器明确拒绝密码（E2553）。继续重试只会增加锁号风险。"""
    return ("E2553" in reason or "Password is error" in reason
            or "密码错误" in reason)


def run_once(verbose: bool = True) -> tuple[bool, str]:
    creds = S.load_credentials()
    if not creds:
        msg = "未配置凭据，请运行 setup.cmd"
        if verbose:
            S.log(msg)
        return False, msg
    return S.ensure_online(*creds, verbose=verbose)


def session_state() -> bool | None:
    """三层探测的主判断：本 IP 是否仍持有门户会话。

    True  = 已认证（走局域网查询，24ms，不消耗外网流量）
    False = 未认证，需要认证
    None  = 门户不可达（没插网线 / 不在校园网）
    """
    return S.portal_session_active(timeout=2.0)


def try_authenticate() -> tuple[bool, bool, str]:
    """尝试恢复联网。

    返回 (是否已在线, 是否处于可认证环境, 失败原因)。
    未插网线/不在校园网时返回 (False, False, 原因)，调用方应静默等待。
    """
    state = session_state()
    if state is None:
        return False, False, "门户不可达"
    if state:
        # 门户认为在线。正常情况下这就够了，但为了排除「会话在、网关不通」
        # 这类边界，由调用方按 EXTERNAL_POLL 周期做外网实测兜底。
        return True, True, ""
    ok, msg = run_once(verbose=False)
    return ok, True, msg


# ---------------------------------------------------------------- 主循环


def daemon_loop() -> int:
    lock = acquire_single_instance()
    if lock is None:
        S.log("已有守护进程在运行，本次退出")
        return 0

    S.log(f"守护进程启动（链路 {LINK_POLL}s / 门户会话 {SESSION_POLL}s / 外网兜底 {EXTERNAL_POLL}s）")
    stop = {"flag": False}

    def _on_signal(signum, frame):
        stop["flag"] = True

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGBREAK):
        try:
            signal.signal(sig, _on_signal)
        except (ValueError, OSError):
            pass

    had_link = False
    fail_streak = 0
    next_session_check = 0.0
    next_external_check = 0.0
    password_dead = False   # 密码错误后停止重试，防止账号被锁
    cred_mtime = _cred_mtime()

    while not stop["flag"]:
        # 单次迭代的任何意外异常都不能让守护进程退出——退出了就再也不会
        # 自动重连，而且用户看不到任何提示。记录后继续下一轮。
        try:
            link = has_link()

            # 链路刚出现（插网线/连上 Wi-Fi/唤醒）：等拿到 IP 就立即认证
            if link and not had_link:
                S.log("检测到网络连接")
                wait_for_link(SETTLE_AFTER_LINK)
                next_session_check = 0.0
                next_external_check = 0.0
            had_link = link

            # 用户重跑 setup.cmd 后（cred.bin 变化），恢复自动认证
            mtime = _cred_mtime()
            if mtime != cred_mtime:
                cred_mtime = mtime
                if password_dead:
                    S.log("检测到凭据已更新，恢复自动认证")
                password_dead = False
                fail_streak = 0
                next_session_check = 0.0

            if not link:
                # 没插网线：什么都不做，静默等待
                for _ in range(LINK_POLL * 4):
                    if stop["flag"]:
                        break
                    time.sleep(0.25)
                continue

            now = time.monotonic()

            # 兜底校验：门户说在线，但偶尔也要真连一次外网，
            # 排除「会话在、网关不通」这类边界。频率低，流量可忽略。
            if now >= next_external_check:
                next_external_check = now + EXTERNAL_POLL
                if session_state() is True and not S.internet_ok():
                    S.log("门户会话仍在但外网不通，重新认证")
                    next_session_check = 0.0

            if not password_dead and now >= next_session_check:
                next_session_check = now + SESSION_POLL
                ok, actionable, reason = try_authenticate()
                if ok:
                    if fail_streak:
                        S.log("已恢复联网")
                    fail_streak = 0
                elif actionable:
                    fail_streak += 1
                    if _is_password_error(reason):
                        password_dead = True
                        S.log("密码错误（E2553），已停止自动重试以免账号被锁定。"
                              "请重新运行 setup.cmd 输入正确密码，保存后本进程会自动恢复。")
                    else:
                        # 开机/刚插网线时的失败多为瞬时（DHCP 未稳、门户未就绪），
                        # 早期用短间隔快速重试，之后指数退避避免打扰门户。
                        backoff = min(10 * (2 ** min(fail_streak - 1, 5)), FAIL_BACKOFF_MAX)
                        S.log(f"认证未成功（第 {fail_streak} 次）：{reason}；{backoff} 秒后重试")
                        next_session_check = time.monotonic() + backoff
        except Exception as exc:
            # 只记录异常类型与消息，不打印 traceback 里的请求 URL（含账号）。
            S.log(f"守护进程遇到异常，已跳过本轮：{type(exc).__name__}: {exc}")
            fail_streak = 0
            next_session_check = time.monotonic() + SESSION_POLL

        for _ in range(LINK_POLL * 4):
            if stop["flag"]:
                break
            time.sleep(0.25)

    S.log("守护进程退出")
    return 0


def main(argv: list[str]) -> int:
    if "--once" in argv:
        ok, _msg = run_once()
        return 0 if ok else 1
    return daemon_loop()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
