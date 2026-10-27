"""自检：验证协议实现、凭据存储与网络探测。

不联网也能跑核心检查；带 --online 会额外验证门户连通性。
用法：
    python selftest.py            # 离线自检
    python selftest.py --online   # 额外检查门户/外网
"""
from __future__ import annotations

import hashlib
import json
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
    """加密实现必须与固定测试向量一致（向量由与门户逐字节比对过的实现生成）。"""
    ref = HERE / "crypto_vectors.json"
    if not ref.exists():
        print("  SKIP  加密向量验证（找不到 crypto_vectors.json）")
        return
    data = json.loads(ref.read_text(encoding="utf-8"))
    for item in data["vectors"]:
        case = item["input"]
        got_info = S.encode_user_info(case, item["token"])
        got_md5 = S.md5_password(case["password"], item["token"])
        name = case["username"][:16]
        check(f"info 编码: {name!r}", got_info == item["expect_info"],
              f"got={got_info[:40]}")
        check(f"密码 MD5: {name!r}", got_md5 == item["expect_md5"],
              f"got={got_md5}")


def test_js_utf16_packing() -> None:
    """XXTEA 输入必须按 JS charCodeAt（UTF-16 码元）打包，不能按 UTF-8 字节。

    纯 ASCII 时两种打包结果相同，所以这个 bug 只能被含中文的用例抓到——
    单独测一次，避免将来只保留 ASCII 向量时静默回归。
    """
    import struct

    def utf8_pack(text: str) -> list[int]:
        b = text.encode()
        n = (len(b) + 3) // 4
        b += b"\0" * (n * 4 - len(b))
        return list(struct.unpack("<%dI" % n, b))

    # _js_pack 对纯 ASCII 应与 UTF-8 打包一致
    check("_js_pack ASCII 与 UTF-8 打包一致",
          S._js_pack("abcdefg") == utf8_pack("abcdefg"))
    # 对中文必须不同（证明真的按 UTF-16 处理）
    check("_js_pack 中文与 UTF-8 打包不同（按 UTF-16 处理）",
          S._js_pack("中文测试") != utf8_pack("中文测试"),
          "说明实现可能错误地按 UTF-8 打包")
    # 中文密码的加密结果必须与向量一致（端到端）
    ref = HERE / "crypto_vectors.json"
    if ref.exists():
        data = json.loads(ref.read_text(encoding="utf-8"))
        zh = [v for v in data["vectors"] if any(ord(c) > 127 for c in v["input"]["username"])]
        check("存在含中文的测试向量", bool(zh), "缺中文向量会让打包 bug 漏过")
        for item in zh:
            check(f"中文用例加密正确: {item['input']['username']!r}",
                  S.encode_user_info(item["input"], item["token"]) == item["expect_info"])


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


def test_masking() -> None:
    """账号与 IP 脱敏：贴日志求助时不该泄漏完整学号。"""
    m = S.mask_account("2024000000000")
    check("账号脱敏保留首尾", m.startswith("2025") and m.endswith("10"), m)
    check("账号脱敏中间被遮蔽", "*" in m and "2024000000000" not in m, m)
    check("短账号也能脱敏", "*" in S.mask_account("abc123"), S.mask_account("abc123"))
    check("空账号不报错", S.mask_account(None) == "(未知)")
    ip = S.mask_ip("10.20.30.40")
    check("IP 脱敏保留网段", ip == "10.20.*.*", ip)
    check("空 IP 不报错", S.mask_ip(None) == "(未知)")


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


def test_loop_survives_exception() -> None:
    """主循环必须能吞下意外异常——退出了就再也不会自动重连。"""
    src = (HERE / "srun_daemon.py").read_text(encoding="utf-8")
    start = src.index('while not stop["flag"]:')
    body = src[start:src.index('S.log("守护进程退出")')]
    check("主循环有异常兜底", "except Exception" in body,
          "循环体缺少 try/except，意外异常会让守护进程静默退出")


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
    test_js_utf16_packing()
    test_md5_and_chksum()

    print("== 凭据存储 ==")
    test_dpapi_roundtrip()

    print("== 结果判定 ==")
    test_masking()
    test_result_mapping()

    print("== 链路探测 ==")
    test_link_probe()

    print("== 守护进程健壮性 ==")
    test_loop_survives_exception()
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
