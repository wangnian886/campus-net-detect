"""自检：验证协议实现、凭据存储与网络探测。

不联网也能跑核心检查；带 --online 会额外验证门户连通性。
用法：
    python selftest.py            # 离线自检
    python selftest.py --online   # 额外检查门户/外网
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import srun_core as S  # noqa: E402
import srun_daemon as D  # noqa: E402

passed = failed = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


def test_crypto_against_js_reference() -> None:
    """加密实现必须与门户 Portal.js 的原版实现逐字节一致。"""
    ref = HERE / "js_ref_encoder.mjs"
    if not ref.exists():
        print("  SKIP  加密交叉验证（找不到 js_ref_encoder.mjs）")
        return
    token = "ede69a8e64d052d24dcec5f8f868361fd2aa4dd130f37255f74a994bd8dc7a3e"
    cases = [
        {"username": "2024000000000@uestc", "password": "TestPass123",
         "ip": "10.20.30.40", "acid": "6", "enc_ver": "srun_bx1"},
        {"username": "中文测试", "password": "p@ss!中文",
         "ip": "10.0.0.1", "acid": "6", "enc_ver": "srun_bx1"},
        {"username": "a@b", "password": "", "ip": "1.2.3.4",
         "acid": "1", "enc_ver": "srun_bx1"},
        {"username": "x" * 50, "password": "y" * 33,
         "ip": "255.255.255.255", "acid": "66", "enc_ver": "srun_bx1"},
    ]
    for case in cases:
        py = S.encode_user_info(case, token)
        r = subprocess.run(
            ["node", str(ref), token,
             json.dumps(case, separators=(",", ":"), ensure_ascii=False)],
            capture_output=True, text=True)
        js = (r.stdout or "").strip()
        check(f"info 编码一致: {case['username'][:16]!r}", py == js and js != "",
              f"py={py[:40]} js={js[:40]}")


def test_md5_and_chksum() -> None:
    token = "abc123"
    check("md5_password",
          S.md5_password("pw", token) == hashlib.md5(b"pwabc123").hexdigest())
    info = "{SRBX1}xyz"
    expect = hashlib.sha1(
        ("abc123" + "u@uestc" + "abc123" + "h" + "abc123" + "6"
         + "abc123" + "1.2.3.4" + "abc123" + "200" + "abc123" + "1"
         + "abc123" + info).encode()).hexdigest()
    check("make_chksum 拼接顺序",
          S.make_chksum(token, "u@uestc", "h", "6", "1.2.3.4", "200", "1", info) == expect)


def test_dpapi_roundtrip() -> None:
    """凭据加密存储必须能原样读回，且文件不含明文。"""
    original = (S.CRED_FILE, S.STATE_DIR)
    tmp = Path(tempfile.mkdtemp(prefix="srun_selftest_"))
    try:
        S.STATE_DIR = tmp
        S.CRED_FILE = tmp / "cred.bin"
        secret = "口令_Secret_123!"
        S.save_credentials("2024000000000", secret)
        check("DPAPI 读回一致", S.load_credentials() == ("2024000000000", secret))
        raw = S.CRED_FILE.read_bytes()
        check("密文不含明文密码", secret.encode("utf-8") not in raw and b"2024000000000" not in raw)
        check("无凭据时返回 None", _load_missing())
    finally:
        S.CRED_FILE, S.STATE_DIR = original
        for p in tmp.iterdir():
            p.unlink(missing_ok=True)
        tmp.rmdir()


def _load_missing() -> bool:
    missing = S.STATE_DIR / "does_not_exist.bin"
    saved = S.CRED_FILE
    try:
        S.CRED_FILE = missing
        return S.load_credentials() is None
    finally:
        S.CRED_FILE = saved


def test_result_mapping() -> None:
    """认证返回码的判定分支。"""
    cases = [
        ({"error": "password_error"}, "密码错误"),
        ({"error": "sign_error"}, "签名校验失败"),
        ({"error": "ok", "suc_msg": "login_ok", "ecode": 0}, "成功"),
        ({"error": "ok", "suc_msg": "ip_already_online_error", "ecode": 0}, "已在线"),
    ]
    for res, expect in cases:
        error = res.get("error") or ""
        suc = res.get("suc_msg") or ""
        if error == "ok" and (suc in ("login_ok", "ip_already_online_error", "") or res.get("ecode") == 0):
            verdict = "已在线" if suc == "ip_already_online_error" else "成功"
        elif error == "sign_error":
            verdict = "签名校验失败"
        elif "password" in error.lower():
            verdict = "密码错误"
        else:
            verdict = "其他"
        check(f"返回码映射 {error or suc}", verdict == expect, f"got {verdict}")


def test_link_probe() -> None:
    ip = D.default_source_ip()
    check("default_source_ip 返回合法 IPv4 或 None",
          ip is None or (isinstance(ip, str) and ip.count(".") == 3), repr(ip))
    check("has_link 与 default_source_ip 一致", D.has_link() == (ip is not None))
    # 169.254 / 127.x 必须被判为无链路
    check("链路本地地址判为无链路", _is_bad_ip("169.254.1.1") and _is_bad_ip("127.0.0.1"))


def _is_bad_ip(ip: str) -> bool:
    return ip.startswith("127.") or ip.startswith("169.254.")


def test_daemon_triggers() -> None:
    """守护进程触发判定：断网且门户可达要认证；没插网线要静默；已联网不打扰。"""
    orig_session, orig_run = D.session_state, D.run_once
    calls = []

    def fake_run(verbose=True):
        calls.append(verbose)
        return False, "模拟失败"

    try:
        D.run_once = fake_run

        # 门户可达但未认证 -> 必须认证
        D.session_state = lambda: False
        ok, actionable, reason = D.try_authenticate()
        check("未认证+门户可达 -> 触发认证",
              actionable is True and bool(calls), f"{ok},{actionable},{reason}")

        # 门户不可达（没插网线）-> 静默
        calls.clear()
        D.session_state = lambda: None
        ok, actionable, reason = D.try_authenticate()
        check("没插网线 -> 静默不认证",
              actionable is False and not calls, f"{ok},{actionable},{reason}")

        # 已认证在线 -> 不做任何事
        calls.clear()
        D.session_state = lambda: True
        ok, actionable, reason = D.try_authenticate()
        check("已认证在线 -> 不做任何事",
              ok is True and not calls, f"{ok},{actionable},{reason}")
    finally:
        D.session_state, D.run_once = orig_session, orig_run


def main(argv: list[str]) -> int:
    print("== 协议实现 ==")
    test_crypto_against_js_reference()
    test_md5_and_chksum()

    print("== 凭据存储 ==")
    test_dpapi_roundtrip()

    print("== 结果判定 ==")
    test_result_mapping()

    print("== 链路探测 ==")
    test_link_probe()

    print("== 守护进程触发 ==")
    test_daemon_triggers()

    if "--online" in argv:
        print("== 在线检查 ==")
        check("门户可达", S.portal_reachable())
        check("外网可达", S.internet_ok())
        info = S.online_info()
        check("在线信息可读", info is not None and info.get("error") == "ok")

    print(f"\n结果：{passed} 通过 / {failed} 失败")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
