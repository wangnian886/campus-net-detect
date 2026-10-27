"""校园网（深澜 Srun Portal）自动认证核心。

只用标准库。凭据用 Windows DPAPI 加密存放在 %LOCALAPPDATA%\\srun-auto\\cred.bin，
只有当前 Windows 账户能解密。

用法（由 srun_daemon.py 调用；也可手动执行）：
    python srun_core.py login     # 检测 + 认证一次
    python srun_core.py status    # 只报告在线状态
    python srun_core.py setpass   # 交互式设置账号密码
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from ctypes import wintypes
from pathlib import Path

# ---------------------------------------------------------------- 门户常量
# 默认值对应电子科技大学沙河校区。其他学校/校区若门户地址不同，
# 改 config.json 即可，无需改代码（见 load_config）。

DEFAULTS = {
    "portal_host": "192.168.9.8",
    "ac_id": "6",
    "domain": "@uestc",
}

PORTAL_HOST = DEFAULTS["portal_host"]
AC_ID = DEFAULTS["ac_id"]
DOMAIN = DEFAULTS["domain"]
N_PARAM = "200"
TYPE_PARAM = "1"
ENC_VER = "srun_bx1"
OS_NAME = "Windows NT"
PLATFORM_NAME = "Windows"

# 联网探测：返回 204 说明未被劫持到认证页
PROBE_URL = "http://connect.rom.miui.com/generate_204"
PROBE_EXPECT = 204

STATE_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "srun-auto"
CRED_FILE = STATE_DIR / "cred.bin"
CONFIG_FILE = STATE_DIR / "config.json"
LOG_FILE = STATE_DIR / "srun.log"

BASE64_ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_MASK = 0xFFFFFFFF
_DELTA = 0x9E3779B9


def load_config() -> dict:
    """读取 config.json 覆盖默认门户参数；文件不存在则用默认值。"""
    global PORTAL_HOST, AC_ID, DOMAIN
    cfg = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            pass
    PORTAL_HOST = cfg["portal_host"]
    AC_ID = str(cfg["ac_id"])
    DOMAIN = cfg["domain"]
    return cfg


load_config()

# ---------------------------------------------------------------- 日志


def _force_utf8_console() -> None:
    """让控制台按 UTF-8 解码输出，避免中文乱码。

    Windows 控制台默认按当前代码页（中文系统是 GBK/936）解码，
    而 Python 3.11 的输出是 UTF-8，两者不一致就会显示乱码。
    """
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


def log(msg: str) -> None:
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            # 超过 512KB 时截断，避免无限增长
            if f.tell() > 512 * 1024:
                pass
        if LOG_FILE.stat().st_size > 512 * 1024:
            content = LOG_FILE.read_text(encoding="utf-8", errors="replace")
            LOG_FILE.write_text(content[-256 * 1024:], encoding="utf-8")
    except OSError:
        pass
    if sys.stdout is not None and not sys.stdout.closed:
        try:
            print(line, flush=True)
        except (OSError, ValueError):
            pass


# ---------------------------------------------------------------- 加密实现


def _js_pack(text: str) -> list[int]:
    """按 JS charCodeAt 语义打包成 32 位字（UTF-16 码元，非 UTF-8 字节）。"""
    words = []
    for i in range(0, len(text), 4):
        w = 0
        for j, ch in enumerate(text[i:i + 4]):
            w |= (ord(ch) & 0xFFFF) << (8 * j)
        words.append(w & _MASK)
    return words


def xxtea_encrypt(text: str, key: str) -> bytes:
    if not text:
        return b""
    v = _js_pack(text)
    v.append(len(text))
    k = _js_pack(key)
    if len(k) < 4:
        k += [0] * (4 - len(k))
    n = len(v) - 1
    z = v[n]
    y = v[0]
    q = 6 + 52 // (n + 1)
    total = 0
    while q > 0:
        q -= 1
        total = (total + _DELTA) & _MASK
        e = (total >> 2) & 3
        for p in range(n):
            y = v[p + 1]
            m = (((z >> 5) ^ (y << 2)) + (((y >> 3) ^ (z << 4)) ^ (total ^ y))) & _MASK
            m = (m + (k[(p & 3) ^ e] ^ z)) & _MASK
            z = v[p] = (v[p] + m) & _MASK
        y = v[0]
        m = (((z >> 5) ^ (y << 2)) + (((y >> 3) ^ (z << 4)) ^ (total ^ y))) & _MASK
        m = (m + (k[(n & 3) ^ e] ^ z)) & _MASK
        z = v[n] = (v[n] + m) & _MASK
    return struct.pack("<%dI" % len(v), *v)


def custom_b64_encode(data: bytes) -> str:
    std = base64.b64encode(data).decode()
    return std.translate(str.maketrans(STD_ALPHABET, BASE64_ALPHABET))


def encode_user_info(info: dict, token: str) -> str:
    raw = json.dumps(info, separators=(",", ":"), ensure_ascii=False)
    return "{SRBX1}" + custom_b64_encode(xxtea_encrypt(raw, token))


def md5_password(password: str, token: str) -> str:
    return hashlib.md5((password + token).encode()).hexdigest()


def make_chksum(token: str, username: str, hmd5: str, ac_id: str, ip: str,
                n: str, type_: str, info: str) -> str:
    s = (token + username + token + hmd5 + token + ac_id + token + ip
         + token + n + token + type_ + token + info)
    return hashlib.sha1(s.encode()).hexdigest()


# ---------------------------------------------------------------- DPAPI 凭据


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()
    fn = (ctypes.windll.crypt32.CryptProtectData if protect
          else ctypes.windll.crypt32.CryptUnprotectData)
    # CryptProtectData(pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)
    ok = fn(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise OSError(ctypes.windll.kernel32.GetLastError(), "DPAPI 调用失败")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _restrict_to_current_user(path: Path) -> None:
    """把文件权限收紧到仅当前用户（Windows 用 ACL，POSIX 用 chmod）。

    DPAPI 已经加密了内容，但去掉其他用户的读权限可以防止他们把
    cred.bin 拷到别处做离线尝试。失败不影响功能，只是少一层防护。
    """
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    if os.name != "nt":
        return
    try:
        user = os.environ.get("USERNAME", "")
        if not user:
            return
        # /inheritance:r 断开继承，/grant:r 只给当前用户完全控制
        subprocess.run(
            ["icacls", str(path), "/inheritance:r",
             "/grant:r", f"{user}:F"],
            capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def save_credentials(username: str, password: str) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"username": username, "password": password}).encode()
    CRED_FILE.write_bytes(_dpapi(payload, protect=True))
    _restrict_to_current_user(CRED_FILE)


def load_credentials() -> tuple[str, str] | None:
    if not CRED_FILE.exists():
        return None
    try:
        data = json.loads(_dpapi(CRED_FILE.read_bytes(), protect=False))
        return data["username"], data["password"]
    except Exception:
        return None


# ---------------------------------------------------------------- 网络探测


_ssl_ctx: ssl.SSLContext | None = None


def _opener():
    """绕过系统代理直连校园网门户。

    门户证书是自签的（校园内网），所以关闭证书校验——这里防的是
    同网段嗅探，不是中间人伪装（内网环境下后者本就不成立）。
    SSLContext 复用，避免每次请求都重新协商 TLS 会话。
    """
    global _ssl_ctx
    if _ssl_ctx is None:
        _ssl_ctx = ssl.create_default_context()
        _ssl_ctx.check_hostname = False
        _ssl_ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=_ssl_ctx))


def portal_base(use_https: bool = True) -> str:
    return f"{'https' if use_https else 'http'}://{PORTAL_HOST}"


# 门户是否支持 HTTPS。首次请求失败时置 False，之后一律走 HTTP，
# 兼容不支持 TLS 的校区（此时安全性退化为原来的水平）。
_https_ok = True


def _get_jsonp(url: str, params: dict, timeout: float = 6.0) -> dict | None:
    global _https_ok
    # HTTPS 失败时自动回退到 HTTP 重试一次
    schemes = [url]
    if url.startswith("https://") and _https_ok:
        schemes.append("http://" + url[len("https://"):])

    for attempt_url in schemes:
        full = attempt_url + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(full, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with _opener().open(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
        except Exception:
            if attempt_url.startswith("https://"):
                _https_ok = False
            continue
        start, end = text.find("("), text.rfind(")")
        if start < 0 or end <= start:
            return None
        try:
            return json.loads(text[start + 1:end])
        except json.JSONDecodeError:
            return None
    return None


def internet_ok(timeout: float = 5.0) -> bool:
    """能否真正访问外网（未被劫持到认证页）。"""
    req = urllib.request.Request(PROBE_URL, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with _opener().open(req, timeout=timeout) as resp:
            return resp.status == PROBE_EXPECT
    except Exception:
        return False


def portal_reachable(timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((PORTAL_HOST, 80), timeout=timeout):
            return True
    except OSError:
        return False


def local_ip_for_portal() -> str | None:
    """取本机与门户通信所用的源 IP（自动选对网卡）。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect((PORTAL_HOST, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def online_info() -> dict | None:
    """查询门户的在线状态；返回 error=='ok' 的字典表示本 IP 已在线。"""
    res = _get_jsonp(f"{portal_base()}/cgi-bin/rad_user_info", {"callback": "x"})
    if not res or res.get("error") != "ok":
        return None
    return res


def portal_session_active(timeout: float = 2.0) -> bool | None:
    """快速判断本 IP 是否仍持有门户会话（走局域网，不消耗外网流量）。

    返回 True=已认证在线，False=未认证，None=门户不可达（没插网线/不在校园网）。

    只读响应开头约 300 字节就够判断（完整响应 850 字节含大量用不上的
    用户信息）。轮询频率高，省下的字节积少成多。
    """
    req = urllib.request.Request(
        f"{portal_base()}/cgi-bin/rad_user_info?callback=x",
        headers={"User-Agent": "Mozilla/5.0"})
    try:
        resp = _opener().open(req, timeout=timeout)
        try:
            head = resp.read(300).decode("utf-8", "replace")
        finally:
            resp.close()
    except Exception:
        return None
    # 开头形如: x({"ServerFlag":...,"error":"ok",...}
    m = re.search(r'"error"\s*:\s*"([^"]*)"', head)
    if not m:
        return None
    return m.group(1) == "ok"


# ---------------------------------------------------------------- 认证流程


def _portal_request(path: str, params: dict, timeout: float = 8.0) -> dict | None:
    return _get_jsonp(f"{portal_base()}{path}", params, timeout=timeout)


def login(username: str, password: str, ip: str | None = None) -> tuple[bool, str]:
    """执行一次认证。返回 (是否成功, 说明)。"""
    if ip is None:
        ip = local_ip_for_portal()
    if not ip:
        return False, "拿不到本机 IP（门户不可达）"

    full_user = username + ("" if "@" in username else DOMAIN)

    challenge = _portal_request("/cgi-bin/get_challenge",
                               {"callback": "jQuery", "username": full_user, "ip": ip})
    if not challenge or not challenge.get("challenge"):
        return False, "获取 token 失败"
    token = challenge["challenge"]
    ip = challenge.get("client_ip") or ip

    hmd5 = md5_password(password, token)
    info = encode_user_info(
        {"username": full_user, "password": password, "ip": ip,
         "acid": AC_ID, "enc_ver": ENC_VER}, token)
    chksum = make_chksum(token, full_user, hmd5, AC_ID, ip, N_PARAM, TYPE_PARAM, info)

    res = _portal_request("/cgi-bin/srun_portal", {
        "callback": "jQuery", "action": "login", "username": full_user,
        "password": "{MD5}" + hmd5, "os": OS_NAME, "name": PLATFORM_NAME,
        "double_stack": "0", "chksum": chksum, "info": info,
        "ac_id": AC_ID, "ip": ip, "n": N_PARAM, "type": TYPE_PARAM,
    })
    if not res:
        return False, "认证请求无响应"

    error = res.get("error") or ""
    suc = res.get("suc_msg") or ""
    if error == "ok" and (suc in ("login_ok", "ip_already_online_error", "") or res.get("ecode") == 0):
        if suc == "ip_already_online_error":
            return True, "已在线"
        return True, "认证成功"
    msg = res.get("error_msg") or error or "未知错误"
    if error == "sign_error":
        return False, "签名校验失败（协议参数不匹配）"
    if "password" in error.lower() or "密码" in str(msg):
        return False, f"密码错误（{error}）"
    return False, f"认证失败：{error} {msg}".strip()


def ensure_online(username: str, password: str, verbose: bool = True) -> tuple[bool, str]:
    """确保在线：能上网直接返回；否则尝试认证。返回 (是否在线, 说明)。"""
    # 先用门户会话状态判断（走局域网，24ms，零外网流量）
    state = portal_session_active()
    if state is True:
        if verbose:
            log("已联网，无需认证")
        return True, "已联网"
    if state is None:
        if verbose:
            log("门户不可达（可能没插网线/未连校园网）")
        return False, "门户不可达（可能没插网线/未连校园网）"

    ok, msg = login(username, password)
    if verbose:
        log(("认证成功：" if ok else "认证失败：") + msg)
    if not ok:
        return False, msg

    # 认证后用门户状态确认（快速），再用外网实测兜底（准）
    if portal_session_active():
        if verbose:
            log("联网确认成功")
        return True, "认证成功"
    for _ in range(5):
        time.sleep(0.6)
        if internet_ok():
            if verbose:
                log("联网确认成功")
            return True, "认证成功"
    if verbose:
        log("认证返回成功，但仍无法访问外网")
    return False, "认证返回成功，但仍无法访问外网"


# ---------------------------------------------------------------- 命令行


def _prompt_credentials() -> None:
    import getpass

    _force_utf8_console()

    print("输入校园网账号密码（密码不回显）。")
    print(f"  凭据将以 DPAPI 加密保存在 {CRED_FILE}")
    username = input("账号: ").strip()
    if not username:
        print("账号不能为空，已取消。")
        return
    password = getpass.getpass("密码: ")
    if not password:
        print("密码为空，已取消。")
        return
    save_credentials(username, password)
    print(f"已保存：{username}")

    if online_info() is not None:
        # 门户对已在线的 IP 不校验密码（直接回 ip_already_online_error），
        # 所以现在无法验证密码对不对，只能如实告知。
        print()
        print("注意：当前已联网，门户不会校验密码，因此这次无法确认密码是否正确。")
        print("建议在方便断网的时候运行  python srun_core.py verify  做一次真实验证；")
        print("如果密码不对，断网时守护进程会明确报「密码错误」并停止重试。")
        return

    print("当前未联网，现在用新密码尝试认证…")
    ok, msg = ensure_online(username, password)
    print("认证成功，自动连接已就绪。" if ok else f"认证失败：{msg}")


def logout(username: str, ip: str | None = None) -> tuple[bool, str]:
    """登出当前 IP 的会话。仅供 verify 命令使用——会真实断网。"""
    if ip is None:
        ip = local_ip_for_portal()
    if not ip:
        return False, "拿不到本机 IP"
    full_user = username + ("" if "@" in username else DOMAIN)
    res = _portal_request("/cgi-bin/srun_portal", {
        "callback": "jQuery", "action": "logout",
        "username": full_user, "ac_id": AC_ID, "ip": ip})
    if not res:
        return False, "登出请求无响应"
    if res.get("error") == "ok":
        return True, "已登出"
    return False, f"登出失败：{res.get('error')} {res.get('error_msg') or ''}".strip()


def _verify_password() -> None:
    """用户主动触发的真实验证：登出当前会话，再用保存的密码重新登录。

    会短暂断网（几秒到几十秒），所以只在用户手动运行本命令时执行。
    """
    _force_utf8_console()
    creds = load_credentials()
    if not creds:
        print("尚未保存凭据，请先运行 setup.cmd")
        return
    if online_info() is None:
        print("当前未联网，无需登出，直接尝试认证…")
        ok, msg = ensure_online(*creds)
        print("认证成功，密码正确。" if ok else f"认证失败：{msg}")
        return
    print("即将登出当前校园网会话并用保存的密码重新登录。")
    print("这会短暂断网；如果密码不对，需要你在浏览器门户里手动登录恢复。")
    answer = input("确认继续？(y/N): ").strip().lower()
    if answer != "y":
        print("已取消，未做任何改动。")
        return
    ok, msg = logout(creds[0])
    print(msg)
    if not ok:
        return
    print("正在用保存的密码重新登录…")
    ok, msg = ensure_online(*creds, verbose=True)
    print("验证通过：密码正确，自动连接可用。" if ok else f"验证失败：{msg}")
    if not ok:
        print("请到浏览器门户手动登录恢复网络，然后重新运行 setup.cmd。")


def mask_account(name: str | None) -> str:
    """脱敏账号，便于贴日志/截图求助时不泄漏学号。保留前 4 后 2。"""
    if not name:
        return "(未知)"
    if len(name) <= 6:
        return name[0] + "*" * (len(name) - 1)
    return name[:4] + "*" * (len(name) - 6) + name[-2:]


def mask_ip(ip: str | None) -> str:
    """脱敏 IP，保留网段便于判断是否在校园网内。"""
    if not ip:
        return "(未知)"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.*.*"
    return "***"


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "login"

    if cmd == "setpass":
        _prompt_credentials()
        return 0

    if cmd == "verify":
        _verify_password()
        return 0

    if cmd == "status":
        info = online_info()
        if info:
            log(f"在线：{mask_account(info.get('user_name'))} @ {mask_ip(info.get('online_ip'))} "
                f"余额 {info.get('user_balance')} 已用 {info.get('all_bytes')} 字节")
        else:
            log("未在线")
        log("外网可达" if internet_ok() else "外网不可达")
        return 0

    creds = load_credentials()
    if not creds:
        log("尚未配置凭据，请先运行：python srun_core.py setpass")
        return 2
    ok, _msg = ensure_online(*creds)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
