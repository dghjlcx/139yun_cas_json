#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
移动云盘(139) CAS 秒传检测/恢复  v2 (含账号密码登录, 无需 OpenList)
对齐 OpenList drivers/139 (personal_new):
  登录:   mail.10086.cn SSO 三步 + user-njs.yun.139.com/user/thirdlogin (AES加密)
  秒传:   {PersonalCloudHost}/file/create (rapidUpload / partInfos / exist)

用法:
  python cas139_check.py 某个.cas [parentFileId=/]

凭证: 二选一
  1) ACCOUNT + PASSWORD      -> 脚本自动登录(推荐, token 缓存到 ~/.cas139_token.json)
  2) AUTH_139                -> 直接填已有 base64 token (跳过登录)
"""
import base64
import hashlib
import json
import os
import random
import re
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar

# ============================================================
# 配置区 (三选一填写)
# ============================================================
ACCOUNT = ""                 # 移动云盘手机号
PASSWORD = ""                # 密码
AUTH_139 = ""                # 或直接填 base64 token (形如 cGM6MTM4MDAwMDAwMDA6...)
PARENT_ID = "/"              # 默认恢复到根目录

TOKEN_CACHE = os.path.join(os.path.expanduser("~"), ".cas139_token.json")

ROUTE_URL = "https://user-njs.yun.139.com/user/route/qryRoutePolicy"
SSO_LOGIN_URL = "https://mail.10086.cn/Login/Login.ashx"
ARTIFACT_URL = "https://smsrebuild1.mail.10086.cn/setting/s"
THIRDLOGIN_URL = "https://user-njs.yun.139.com/user/thirdlogin"
REFRESH_URL = "https://aas.caiyun.feixin.10086.cn:443/tellin/authTokenRefresh.do"

# 驱动内置常量 (util.go)
KEY1 = bytes.fromhex("73634235495062495331515373756c734e7253306c673d3d")  # AES-192 (第一层CBC)
KEY2 = bytes.fromhex("7150714477236333586746674c337538")                  # AES-128 (第二层ECB)
CLIENT_KEY = "l3TryM&Q+X@dzwk)qP"

HEADERS_BASE = {
    "Accept": "application/json, text/plain, */*",
    "Cms-Device": "default",
    "mcloud-channel": "1000101",
    "mcloud-client": "10701",
    "mcloud-version": "7.14.0",
    "Origin": "https://yun.139.com",
    "Referer": "https://yun.139.com/w/",
    "x-DeviceInfo": "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||",
    "x-huawei-channelSrc": "10000034",
    "x-inner-ntwk": "2",
    "x-m4c-caller": "PC",
    "x-m4c-src": "10002",
    "x-SvcType": "1",
    "Inner-Hcy-Router-Https": "1",
}


class Cas139Error(Exception):
    pass


class Cas139AuthError(Cas139Error):
    """凭证被服务端拒绝 (token 失效/账号异常)"""


# ============================================================
# 纯 Python AES-128/192/256 (加解密, 对齐 Go crypto/aes)
# ============================================================
SBOX = (
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16)
INV_SBOX = [0]*256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
INV_SBOX = tuple(INV_SBOX)
RCON = (0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d)

def _xtime(a):
    return (((a << 1) ^ 0x1b) & 0xff) if (a & 0x80) else (a << 1)

def _mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r

def _expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    kc = [list(key[i:i+4]) for i in range(0, len(key), 4)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(kc[i-1])
        if i % nk == 0:
            t = [SBOX[b] for b in (t[1:] + t[:1])]
            t[0] ^= RCON[i//nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        kc.append([kc[i-nk][j] ^ t[j] for j in range(4)])
    return [sum(kc[r*4:(r+1)*4], []) for r in range(nr + 1)], nr

def _shift_rows(s):
    s[1],s[5],s[9],s[13] = s[5],s[9],s[13],s[1]
    s[2],s[6],s[10],s[14] = s[10],s[14],s[2],s[6]
    s[3],s[7],s[11],s[15] = s[15],s[3],s[7],s[11]

def _inv_shift_rows(s):
    s[1],s[5],s[9],s[13] = s[13],s[1],s[5],s[9]
    s[2],s[6],s[10],s[14] = s[10],s[14],s[2],s[6]
    s[3],s[7],s[11],s[15] = s[7],s[11],s[15],s[3]

def _mix_columns(s):
    for c in range(4):
        a = s[c*4:c*4+4]
        t = a[0]^a[1]^a[2]^a[3]
        u = a[0]
        s[c*4+0] ^= t ^ _xtime(a[0]^a[1])
        s[c*4+1] ^= t ^ _xtime(a[1]^a[2])
        s[c*4+2] ^= t ^ _xtime(a[2]^a[3])
        s[c*4+3] ^= t ^ _xtime(a[3]^u)

def _inv_mix_columns(s):
    for c in range(4):
        a = s[c*4:c*4+4]
        s[c*4+0] = _mul(a[0],14)^_mul(a[1],11)^_mul(a[2],13)^_mul(a[3],9)
        s[c*4+1] = _mul(a[0],9)^_mul(a[1],14)^_mul(a[2],11)^_mul(a[3],13)
        s[c*4+2] = _mul(a[0],13)^_mul(a[1],9)^_mul(a[2],14)^_mul(a[3],11)
        s[c*4+3] = _mul(a[0],11)^_mul(a[1],13)^_mul(a[2],9)^_mul(a[3],14)

def _aes_block(block, rks, nr, decrypt=False):
    s = list(block)
    if not decrypt:
        for i in range(16): s[i] ^= rks[0][i]
        for r in range(1, nr):
            for i in range(16): s[i] = SBOX[s[i]]
            _shift_rows(s); _mix_columns(s)
            for i in range(16): s[i] ^= rks[r][i]
        for i in range(16): s[i] = SBOX[s[i]]
        _shift_rows(s)
        for i in range(16): s[i] ^= rks[nr][i]
    else:
        for i in range(16): s[i] ^= rks[nr][i]
        for r in range(nr-1, 0, -1):
            _inv_shift_rows(s)
            for i in range(16): s[i] = INV_SBOX[s[i]]
            for i in range(16): s[i] ^= rks[r][i]
            _inv_mix_columns(s)
        _inv_shift_rows(s)
        for i in range(16): s[i] = INV_SBOX[s[i]]
        for i in range(16): s[i] ^= rks[0][i]
    return bytes(s)

def aes_cbc_encrypt(data, key, iv):
    rks, nr = _expand_key(key)
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i+16], prev))
        prev = _aes_block(blk, rks, nr)
        out += prev
    return out

def aes_cbc_decrypt(data, key, iv):
    rks, nr = _expand_key(key)
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        blk = _aes_block(data[i:i+16], rks, nr, decrypt=True)
        out += bytes(a ^ b for a, b in zip(blk, prev))
        prev = data[i:i+16]
    pad = out[-1]
    return out[:-pad]

def aes_ecb_decrypt(data, key):
    rks, nr = _expand_key(key)
    out = b"".join(_aes_block(data[i:i+16], rks, nr, decrypt=True) for i in range(0, len(data), 16))
    pad = out[-1]
    return out[:-pad]


def sorted_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ============================================================
# 登录 (三步, 对齐 util.go loginWithPassword)
# ============================================================
def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()


def _jar_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)), jar


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def login(account, password):
    print("[登录] 开始 mail.10086.cn SSO 三步登录...")
    opener, jar = _jar_opener()
    b64_acc = base64.b64encode(account.encode()).decode()
    cguid = str(int(time.time() * 1000))
    default_page = ("https://mail.10086.cn/default.html?s=1&v=0&u=" + b64_acc +
                    "&m=1&ec=S001&resource=indexLogin&clientid=1003&auto=on&cguid=" + cguid)

    # ---- 第0步: 取邮箱站初始 Cookie (RMKEY 等), 对应驱动里 MailCookies 的来源 ----
    req = urllib.request.Request(default_page, headers={"User-Agent": "Mozilla/5.0"})
    try:
        opener.open(req, timeout=30).read()
    except Exception:
        pass
    mail_cookies = "; ".join(f"{c.name}={c.value}" for c in jar)

    # ---- 第1步: 邮箱站密码登录, 密码 = SHA1("fetion.com.cn:" + pwd) ----
    form = urllib.parse.urlencode({
        "UserName": account, "passOld": "", "auto": "on",
        "Password": sha1_hex("fetion.com.cn:" + password),
        "webIndexPagePwdLogin": "1", "pwdType": "1",
        "clientId": "1003", "authType": "2",
    })
    req = urllib.request.Request(SSO_LOGIN_URL, data=form.encode(), method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": mail_cookies,
        "Referer": default_page,
        "Origin": "https://mail.10086.cn",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
    })
    no_redirect = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect())
    try:
        resp = no_redirect.open(req, timeout=30)
        resp.read()
        location = resp.headers.get("Location", "")
        status = resp.status
    except urllib.error.HTTPError as e:
        location = e.headers.get("Location", "")
        status = e.code
    sid_m = re.search(r"sid=([^&]+)", location)
    sid = sid_m.group(1) if sid_m else ""
    if not sid:  # 兼容 Set-Cookie 里的 Os_SSo_Sid
        for c in jar:
            if c.name in ("Os_SSo_Sid", "Os_SSO_Sid"):
                sid = c.value
    if not sid:
        raise Cas139Error(f"第1步未取到 sid (HTTP {status}, Location={location[:120]})")
    mail_cookies = "; ".join(f"{c.name}={c.value}" for c in jar)
    print(f"[登录] 第1步 OK (sid=...{sid[-6:]})")

    # ---- 第2步: 换 artifact (短信站, 只用 RMKEY cookie) ----
    rmkey = ""
    for part in mail_cookies.split(";"):
        part = part.strip()
        if part.startswith("RMKEY="):
            rmkey = part
    if not rmkey:
        raise Cas139Error("第2步未找到 RMKEY cookie")
    cguid2 = str(int(time.time() * 1000))
    art_url = f"{ARTIFACT_URL}?func={urllib.parse.quote('umc:getArtifact')}&sid={sid}&cguid={cguid2}"
    req = urllib.request.Request(art_url, data=b"", method="POST", headers={
        "Host": "smsrebuild1.mail.10086.cn",
        "Cookie": rmkey,
        "Content-Type": "text/xml; charset=utf-8",
        "User-Agent": "okhttp/4.12.0",
    })
    art_body = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
    m = re.search(r'"artifact"\s*:\s*"([^"]+)"', art_body) or re.search(r'artifact\s*[:=]\s*"([^"]+)"', art_body)
    if not m:
        raise Cas139Error(f"第2步未取到 artifact: {art_body[:200]}")
    artifact = m.group(1)
    print("[登录] 第2步 OK (artifact 已获取)")

    # ---- 第3步: 139 thirdlogin (AES-192-CBC 加密请求 + AES-128-ECB 二层解密) ----
    body = {
        "clientkey_decrypt": CLIENT_KEY,
        "clienttype": "886", "cpid": "507",
        "dycpwd": artifact,
        "extInfo": {"ifOpenAccount": "0"},
        "loginMode": "0",
        "msisdn": account,
        "pintype": "13",
        "secinfo": sha1_hex("fetion.com.cn:" + artifact).upper(),
        "version": "20250901",
    }
    payload = base64.b64encode(
        (iv := os.urandom(16)) + aes_cbc_encrypt(sorted_json(body).encode(), KEY1, iv)).decode()
    req = urllib.request.Request(THIRDLOGIN_URL, data=payload.encode(), method="POST", headers={
        "hcy-cool-flag": "1",
        "x-huawei-channelSrc": "10246600",
        "x-sdk-channelSrc": "",
        "x-MM-Source": "0",
        "x-User-Agent": "android|23116PN5BC|android15|1.2.6|||1440x3200|10246600",
        "x-DeviceInfo": "4|127.0.0.1|5|1.2.6|Xiaomi|23116PN5BC||02-00-00-00-00-00|android 15|1440x3200|android|||",
        "Content-Type": "text/plain;charset=UTF-8",
        "User-Agent": "okhttp/3.12.2",
    })
    raw = urllib.request.urlopen(req, timeout=30).read()
    txt = raw.decode("utf-8", "replace").strip()
    if txt.startswith("{"):
        layer1 = json.loads(txt)
    else:
        blob = base64.b64decode(txt)
        layer1 = json.loads(aes_cbc_decrypt(blob[16:], KEY1, blob[:16]))
    if "data" not in layer1:
        raise Cas139Error(f"第3步一层解密无 data: {json.dumps(layer1, ensure_ascii=False)[:300]}")
    inner = aes_ecb_decrypt(bytes.fromhex(layer1["data"]), KEY2)
    final = json.loads(inner)
    auth_token = final.get("authToken", "")
    if not auth_token:
        raise Cas139Error(f"第3步未取到 authToken: {inner[:300]}")
    account_ret = final.get("account", account)
    auth = base64.b64encode(f"pc:{account_ret}:{auth_token}".encode()).decode()
    cache_token(auth, account_ret)
    print(f"[登录] 第3步 OK, Authorization 已生成并缓存 (account={account_ret})")
    return auth


def cache_token(auth, account):
    try:
        with open(TOKEN_CACHE, "w") as f:
            json.dump({"auth": auth, "account": account, "saved": int(time.time())}, f)
        os.chmod(TOKEN_CACHE, 0o600)
    except OSError:
        pass


def load_cached_token():
    try:
        d = json.load(open(TOKEN_CACHE))
        auth = d["auth"]
        decoded = base64.b64decode(auth).decode()
        parts = decoded.split(":")
        if len(parts) < 3:
            return None
        toks = parts[2].split("|")
        if len(toks) < 4:
            return None
        exp = int(toks[3]) // 1000
        now = time.time()
        if exp > now:
            return auth  # 未过期 (临期的先用, API 报 auth 错会自动重登)
        return None
    except Exception:
        return None


def ensure_auth():
    if AUTH_139:
        return AUTH_139
    cached = load_cached_token()
    if cached:
        print("[凭证] 使用本地缓存 token")
        return cached
    if not (ACCOUNT and PASSWORD):
        raise Cas139Error("尚未配置凭证: 请打开脚本, 在顶部配置区填写 ACCOUNT(手机号)+PASSWORD, "
                          "或 AUTH_139(已有token), 保存后重新运行")
    return login(ACCOUNT, PASSWORD)


# ============================================================
# mcloud-sign 与业务请求
# ============================================================
def _md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def cal_sign(body, ts, rand_str):
    enc = urllib.parse.quote(body, safe="~!*'()-._")
    joined = "".join(sorted(enc))
    b64 = base64.b64encode(joined.encode()).decode()
    return _md5(_md5(b64) + _md5(f"{ts}:{rand_str}")).upper()

def get_account(auth):
    return base64.b64decode(auth).decode("utf-8", "replace").split(":")[1]

def cloud_request(url, body_obj, auth, extra_headers=None, timeout=30):
    body = json.dumps(body_obj, separators=(",", ":"), ensure_ascii=False)
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    rand = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    headers = dict(HEADERS_BASE)
    headers["Content-Type"] = "application/json;charset=UTF-8"
    headers["Authorization"] = "Basic " + auth
    headers["mcloud-sign"] = f"{ts},{rand},{cal_sign(body, ts, rand)}"
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=body.encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raise Cas139Error(f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:300]}")
    if isinstance(resp, dict) and resp.get("success") is False:
        msg = f"code={resp.get('code')} message={resp.get('message')}"
        low = msg.lower()
        if any(k in low for k in ("token", "auth", "登录", "登陆", "失效", "过期")):
            raise Cas139AuthError(f"服务端拒绝凭证: {msg}")
        raise Cas139Error(f"API返回失败: {msg} | 完整响应: {json.dumps(resp, ensure_ascii=False)[:300]}")
    return resp

def get_personal_host(auth):
    resp = cloud_request(ROUTE_URL, {
        "userInfo": {"userType": 1, "accountType": 1, "accountName": get_account(auth)},
        "modAddrType": 1}, auth)
    data = resp.get("data") or {}
    for pol in data.get("routePolicyList", []):
        if pol.get("modName") == "personal":
            return pol["httpsUrl"].rstrip("/")
    raise Cas139Error(f"路由策略响应异常 (data 为空或无 personal): {json.dumps(resp, ensure_ascii=False)[:400]}")

def make_part_infos(size):
    part_size = 512 * 1024 * 1024 if size // (1024 ** 3) > 30 else 100 * 1024 * 1024
    n = (size + part_size - 1) // part_size
    return [{"partNumber": i + 1, "partSize": min(part_size, size - i * part_size),
             "parallelHashCtx": {"partOffset": i * part_size}} for i in range(min(n, 100))]


PERSONAL_HEADERS = {
    "Caller": "web",
    "Mcloud-Route": "001",
    "X-Yun-Api-Version": "v1",
    "X-Yun-App-Channel": "10000034",
    "X-Yun-Channel-Source": "10000034",
    "X-Yun-Client-Info": "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||dW5kZWZpbmVk||",
    "X-Yun-Module-Type": "100",
    "X-Yun-SvcType": "1",
}


def get_download_url(host, auth, file_id):
    """对应 personalGetLink: POST /file/getDownloadUrl {"fileId": ...}"""
    resp = cloud_request(host + "/file/getDownloadUrl", {"fileId": str(file_id)}, auth, PERSONAL_HEADERS)
    data = resp.get("data")
    if isinstance(data, str) and data.startswith("http"):
        return data
    if isinstance(data, dict):
        for k in ("downloadUrl", "downloadURL", "url", "fileUrl", "cdnUrl"):
            if data.get(k):
                return data[k]
    raise Cas139Error(f"下载地址响应异常: {json.dumps(resp, ensure_ascii=False)[:300]}")


def list_dir(host, auth, parent):
    """POST /file/list 取目录内容 (对齐 List())"""
    resp = cloud_request(host + "/file/list", {
        "parentFileId": parent,
        "pageInfo": {"page": 1, "pageSize": 200, "sortField": "lastOpTime", "sortAsc": False},
    }, auth, PERSONAL_HEADERS)
    data = resp.get("data") or {}
    for k in ("items", "content", "contentList", "files", "list"):
        if isinstance(data.get(k), list):
            return data[k]
    raise Cas139Error(f"目录列表响应异常: {json.dumps(resp, ensure_ascii=False)[:300]}")


def find_file_in_dir(host, auth, parent, name):
    for f in list_dir(host, auth, parent):
        if f.get("type") == "folder" or f.get("isFolder") or f.get("isDir"):
            continue
        if f.get("name") == name:
            return f
    return None


def fetch_and_print_url(host, auth, fid, label=""):
    t = time.perf_counter()
    dl = get_download_url(host, auth, fid)
    print(f"[直链{label}] {dl}")
    print(f"          (取址 {time.perf_counter()-t:.2f}s, 链接有时效, 尽快使用)")
    return dl


def parse_expiry(url):
    """AWS4 预签名URL: 到期 = X-Amz-Date(UTC) + X-Amz-Expires(秒)"""
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    date_s = q.get("X-Amz-Date", [""])[0]
    exp_s = q.get("X-Amz-Expires", ["0"])[0]
    if not date_s:
        return None
    try:
        from datetime import datetime, timezone, timedelta
        sign_time = datetime.strptime(date_s, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        expiry = sign_time + timedelta(seconds=int(exp_s))
        return expiry.astimezone()
    except Exception:
        return None


def print_expiry(url):
    expiry = parse_expiry(url)
    if expiry:
        left = expiry.timestamp() - time.time()
        m, sec = divmod(max(int(left), 0), 60)
        print(f"[到期] {expiry.strftime('%Y-%m-%d %H:%M:%S')} (本地时区), 还剩 {m}分{sec:02d}秒")
    else:
        print("[到期] 链接中无 X-Amz-Date/Expires 参数, 无法推算 (可能不是AWS4签名)")


def delete_file(host, auth, fid):
    """POST /recyclebin/batchTrash -> 移入回收站 (对齐驱动 Remove, 端点不是/file/delete!)"""
    resp = cloud_request(host + "/recyclebin/batchTrash", {"fileIds": [str(fid)]}, auth, PERSONAL_HEADERS)
    if resp.get("success") is False:
        raise Cas139Error(f"删除失败: {json.dumps(resp, ensure_ascii=False)[:200]}")
    return True


def probe_url(url):
    """Range 拉1字节验证链接是否仍可下载"""
    try:
        req = urllib.request.Request(url)
        req.add_header("Range", "bytes=0-0")
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read(1)
            return f"HTTP {r.status} (可下载)"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code} (不可下载: {e.reason})"
    except Exception as e:
        return f"探测失败: {e!r}"


def test_cas(path, parent="/"):
    info = decode_cas(path)
    print(f"CAS: {info['name']}  {info['size']:,} B  {info['algo']}={info['hash'][:32]}...")
    if info["algo"] != "SHA256":
        raise Cas139Error("这是天翼格式 CAS, 139 只认 sha256")

    def _get_host(a):
        return get_personal_host(a)

    auth = ensure_auth()
    try:
        t = time.perf_counter()
        host = _get_host(auth)
    except Cas139AuthError as e:
        if AUTH_139:
            raise Cas139Error(f"{e} | 你填的 AUTH_139 已失效, 请更新, 或改用 ACCOUNT+PASSWORD 自动登录")
        print(f"[凭证] {e}")
        print("[凭证] 清除缓存, 重新登录...")
        if os.path.exists(TOKEN_CACHE):
            os.remove(TOKEN_CACHE)
        auth = ensure_auth()
        host = _get_host(auth)
    print(f"个人云接入点: {host}  ({time.perf_counter()-t:.2f}s)")

    body = {
        "contentHash": info["hash"], "contentHashAlgorithm": "SHA256",
        "contentType": "application/octet-stream", "parallelUpload": False,
        "partInfos": make_part_infos(info["size"]), "size": info["size"],
        "parentFileId": parent, "name": info["name"], "type": "file",
        "fileRenameMode": "auto_rename",
    }
    resp = cloud_request(host + "/file/create", body, auth, PERSONAL_HEADERS)
    if not resp.get("success", True):
        msg = json.dumps(resp, ensure_ascii=False)[:200]
        if "token" in msg.lower() or "登录" in msg or "auth" in msg.lower():
            print("[凭证] 缓存 token 失效, 重新登录...")
            os.path.exists(TOKEN_CACHE) and os.remove(TOKEN_CACHE)
            return test_cas(path, parent)
        raise Cas139Error(f"API 失败: {msg}")
    data = resp.get("data", {})

    if data.get("exist"):
        print("[=] 目录已存在同名文件 (exist=true)")
        fid, src = data.get("fileId"), "create响应"
        fobj = None
        if not fid:
            # create 响应没带 fileId -> 按名字在目标目录里找
            fobj = find_file_in_dir(host, auth, parent, info["name"])
            if fobj:
                fid = fobj.get("fileId") or fobj.get("fileID") or fobj.get("id")
                src = "目录列表"
        if not fid:
            raise Cas139Error("exist=true 但 create 响应与目录列表都未找到文件ID, "
                              f"完整响应: {json.dumps(resp, ensure_ascii=False)[:300]}")
        # 内容一致性核对 (exist 仅代表同名, 未必同内容)
        actual_size = (fobj or data).get("size")
        actual_digest = (fobj or {}).get("digest") or (fobj or {}).get("contentHash") or ""
        if actual_size is not None and int(actual_size) != info["size"]:
            print(f"[!] 警告: 同名文件大小不一致 (网盘 {int(actual_size):,} B != CAS {info['size']:,} B), "
                  "直链指向的可能不是 CAS 对应的内容!")
        elif actual_digest and actual_digest.lower() != info["hash"].lower():
            print(f"[!] 警告: 同名文件摘要与 CAS 不一致, 直链指向的可能不是同一份内容!")
        fetch_and_print_url(host, auth, fid, f"(来源:{src})")
        return "exist"
    if data.get("rapidUpload") and not data.get("partInfos"):
        fid = data.get("fileId", "")
        print(f"[√] 秒传成功! fileId={fid} fileName={data.get('fileName')}")
        try:
            dl = fetch_and_print_url(host, auth, fid)
            print_expiry(dl)
        except Cas139Error as e:
            print(f"[!] 取直链失败(不影响秒传结果): {e}")
            return "rapid"
        # 占用空间测试: 取址后删除刚恢复的文件, 验证链接是否仍然有效
        try:
            ans = input("\n[测试] 是否删除刚恢复的文件以验证CAS玩法? (回车=删除, n=保留): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans in ("", "y", "yes", "是"):
            try:
                delete_file(host, auth, fid)
                print(f"[已删除] fileId={fid} (已移入回收站; 若空间未释放, 需网页端清空回收站)")
                print(f"[验证] 删除后链接存活探测: {probe_url(dl)}")
            except Cas139Error as e:
                print(f"[×] 删除失败: {e}")
        return "rapid"
    if data.get("partInfos"):
        print(f"[×] 秒传未命中: 服务端返回 {len(data['partInfos'])} 个真实上传地址 -> CAS 已失效或从未上传")
        return "miss"
    print(f"[?] 未知响应: {json.dumps(data, ensure_ascii=False)[:300]}")
    return "unknown"


def decode_cas(path):
    raw = open(path, encoding="ascii", errors="replace").read().strip()
    try:
        js = base64.b64decode(raw).decode("utf-8", "replace")
    except Exception:
        js = raw
    d = json.loads(js)
    if d.get("sha256"):
        return {"name": d["name"], "size": int(d["size"]), "hash": d["sha256"], "algo": "SHA256"}
    if d.get("md5"):
        return {"name": d["name"], "size": int(d["size"]),
                "hash": d["md5"], "slice": d.get("sliceMd5", ""), "algo": "TY189"}
    raise Cas139Error("CAS 中没有可用哈希")


def main():
    args = sys.argv[1:]
    if args:
        path = args[0].strip('"').strip("'")
        parent = args[1] if len(args) > 1 else PARENT_ID
    else:
        # IDE 直接运行时无参数 -> 交互式询问
        print("=" * 50)
        print("移动云盘(139) CAS 秒传检测/恢复")
        print("=" * 50)
        try:
            path = input("\n[CAS 文件路径] ").strip().strip('"').strip("'")
            if not path:
                return
            parent = input("[目标目录ID] (回车=根目录 /): ").strip() or PARENT_ID
        except (EOFError, KeyboardInterrupt):
            return
    if not os.path.isfile(path):
        print(f"[×] 文件不存在: {path}")
        return
    try:
        test_cas(path, parent)
    except Cas139Error as e:
        print(f"\n[×] 失败: {e}")
    except Exception as e:
        import traceback
        print(f"\n[×] 未预期错误: {e!r}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
