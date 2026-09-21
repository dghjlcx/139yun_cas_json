#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
资源分享JSON -> 移动云盘(139) CAS 批量转换器 v3

- 控制台输入文件夹, 批量转换全部 JSON
- name 直接用 JSON 文件名 (多条目自动 _2/_3 后缀), 忽略条目内路径
- 全批次统一使用脚本启动时间戳
- SQLite 去重库: 每条 (json路径, 文件名, sha256, 大小) 入库, sha256 主键自动去重
- Windows 文件名加固: 非法字符/尾随空格点/保留名(CON等)全部处理, 单个文件写盘失败不再中断批次

统计口径:
  生成 N   成功产出 N 个 .cas      重复 N   该sha256已入库过(去重)
  重命名 N 同目录同名加_1/_2后缀   写失败 N 写盘错误(已跳过, 批次继续)
  无sha N  缺sha256跳过            跳过 N  非法sha/大小为0/空名
"""
import base64
import json
import os
import re
import sqlite3
import sys
import time
import zipfile

ILLEGAL = re.compile(r'[\\/:*?"<>|]')
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
WIN_RESERVED = {"CON", "PRN", "AUX", "NUL",
                "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
                "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"}
START_TS = str(int(time.time()))      # 全批次统一时间戳


def sanitize_seg(name: str) -> str:
    """Windows安全段: 非法字符+尾随空格点+保留名"""
    name = ILLEGAL.sub("_", name).rstrip(" .")
    if not name:
        name = "_"
    if name.upper() in WIN_RESERVED:
        name = "_" + name
    return name


def sanitize_rel(rel: str) -> str:
    return "/".join(sanitize_seg(p) for p in rel.replace("\\", "/").split("/") if p not in ("", ".", ".."))


def encode_cas(name, size, sha256):
    payload = {
        "name": name, "size": size, "md5": "", "sliceMd5": "",
        "sha256": sha256, "recover_pass": "",
        "create_time": START_TS,
    }
    js = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(js.encode()).decode()


def load_entries(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    return v
            return [data]
        return data
    except json.JSONDecodeError:
        entries, invalid = [], 0
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    invalid += 1
        if not entries and invalid:
            raise ValueError(f"无法解析 ({invalid} 行无效)")
        return entries


def dedup_name(base, used_set):
    if base not in used_set:
        used_set.add(base)
        return base
    stem, ext = os.path.splitext(base)
    n = 1
    while f"{stem}_{n}{ext}" in used_set:
        n += 1
    name = f"{stem}_{n}{ext}"
    used_set.add(name)
    return name


def stem_with_ext(stem: str, entry_name: str) -> str:
    """主体名用JSON stem, 扩展名从条目name的最后一段提取后拼接; stem已带该后缀则不重复拼"""
    base = re.split(r"[/\\]", str(entry_name))[-1]
    m = re.search(r"(\.[^./\\]+)$", base)
    ext = m.group(1) if m else ""
    if ext and not stem.lower().endswith(ext.lower()):
        return stem + ext
    return stem


def collect_json_files(folder, recursive):
    out = []
    if recursive:
        for root, _, names in os.walk(folder):
            for n in sorted(names):
                if n.lower().endswith(".json"):
                    out.append(os.path.join(root, n))
    else:
        for n in sorted(os.listdir(folder)):
            p = os.path.join(folder, n)
            if os.path.isfile(p) and n.lower().endswith(".json"):
                out.append(p)
    return out


def open_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")       # 写前日志, 快且防崩
    conn.execute("PRAGMA synchronous=NORMAL")     # 避免每条fsync (崩溃最多丢最后一文件)
    conn.execute("""CREATE TABLE IF NOT EXISTS cas(
        sha256 TEXT PRIMARY KEY, name TEXT, json_path TEXT, size INTEGER, ts TEXT)""")
    conn.commit()
    return conn


def convert_file(path, json_rel_dir, json_stem, zip_mode, out_zip, out_dir, used, conn):
    st = dict(ok=0, renamed=0, no_sha=0, bad=0, empty=0, werr=0, dup=0, error=None)
    try:
        entries = load_entries(path)
    except Exception as e:
        st["error"] = f"读取失败: {e}"
        return st

    def valid(e):
        if not isinstance(e, dict):
            return None
        sha = str(e.get("sha256", "")).strip().lower()
        if not SHA_RE.match(sha) or re.match(r"^0{64}$", sha):
            return None
        try:
            size = int(e.get("size", 0))
        except (TypeError, ValueError):
            size = 0
        if size <= 0:
            return None
        return sha, size

    # 先数有效条目: 单条(电影)用JSON文件名; 多条(剧集)用条目自己的文件名
    multi = sum(1 for e in entries if valid(e)) > 1

    good_idx = 0
    for e in entries:
        if not isinstance(e, dict):
            st["bad"] += 1
            continue
        v = valid(e)
        if v is None:
            if isinstance(e, dict) and not str(e.get("sha256", "")).strip():
                st["no_sha"] += 1
            else:
                st["bad"] += 1
            continue
        sha, size = v

        # 名称: 电影=JSON文件名+条目扩展名; 剧集=条目自己的文件名(保留E01等集数信息)
        full_entry_name = str(e.get("name", ""))
        if multi:
            base = full_entry_name.replace("\\", "/").rsplit("/", 1)[-1].strip() or json_stem
        else:
            base = stem_with_ext(json_stem, full_entry_name)
        good_idx += 1

        key = json_rel_dir or "@root@"
        if key not in used:
            used[key] = set()
        fname = dedup_name(sanitize_seg(base), used[key])
        if fname != sanitize_seg(base):
            st["renamed"] += 1
        cas = encode_cas(base, size, sha)
        out_rel = (json_rel_dir + "/" if json_rel_dir else "") + fname + ".cas"

        # SQLite 去重 (主键冲突=重复)
        cur = conn.execute(
            "INSERT OR IGNORE INTO cas(sha256, name, json_path, size, ts) VALUES (?,?,?,?,?)",
            (sha, fname, path, size, START_TS))
        if cur.rowcount == 0:
            st["dup"] += 1

        # 写盘 (单个失败不中断批次)
        try:
            if zip_mode:
                out_zip.writestr(out_rel, cas)
            else:
                target = os.path.join(out_dir, *out_rel.split("/"))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w", encoding="ascii") as f:
                    f.write(cas)
            st["ok"] += 1
        except OSError as ex:
            st["werr"] += 1
            if st["werr"] <= 5:
                print(f"    [写失败] {out_rel}: {ex}")
    conn.commit()   # 每个文件一次提交, 而非每条目
    return st


def main():
    args = sys.argv[1:]
    recursive = "-r" in args or "--recursive" in args
    args = [a for a in args if a not in ("-r", "--recursive")]
    db_path = None
    for i, a in enumerate(list(args)):
        if a == "--db" and i + 1 < len(args):
            db_path = args[i + 1]
            args = args[:i] + args[i + 2:]
            break

    if args:
        folder = args[0].strip('"').strip("'")
        out = args[1].strip('"').strip("'") if len(args) > 1 else None
    else:
        print("=" * 52)
        print("分享JSON -> 139 CAS 批量转换器 v3")
        print("=" * 52)
        folder = input("\n[JSON文件夹路径] ").strip().strip('"').strip("'")
        if not folder:
            return
        r = input("[包含子文件夹?] (y/n, 回车=n): ").strip().lower()
        recursive = r in ("y", "yes", "是")
        out = input("[输出路径] (回车=文件夹内新建 cas_out; .zip结尾打ZIP): ").strip().strip('"').strip("'")

    if not os.path.isdir(folder):
        print(f"[×] 文件夹不存在: {folder}")
        return

    files = collect_json_files(folder, recursive)
    if not files:
        print(f"[×] 没有找到 JSON 文件: {folder}")
        return
    if not db_path:
        db_path = os.path.join(folder, "cas_records.db")

    zip_mode = bool(out) and out.lower().endswith(".zip")
    if not out:
        out = os.path.join(folder, "cas_out")
    if zip_mode:
        out_zip = zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED)
        out_dir = None
    else:
        os.makedirs(out, exist_ok=True)
        out_dir = out
        out_zip = None

    conn = open_db(db_path)
    print(f"\n找到 {len(files)} 个 JSON -> {out}{' (ZIP)' if zip_mode else ''}")
    print(f"去重库: {db_path} (统一时间戳 {START_TS})\n")

    used = {}
    tot = dict(ok=0, renamed=0, no_sha=0, bad=0, empty=0, werr=0, dup=0, files=0)
    t0 = time.time()
    for i, fp in enumerate(files, 1):
        rel = os.path.relpath(fp, folder)
        json_rel_dir = sanitize_rel(os.path.dirname(rel).replace(os.sep, "/"))
        json_stem = sanitize_seg(os.path.splitext(os.path.basename(fp))[0])
        st = convert_file(fp, json_rel_dir, json_stem, zip_mode, out_zip, out_dir, used, conn)
        if st["error"]:
            print(f"  [{i}/{len(files)}] {os.path.basename(fp)}: ✗ {st['error']}")
            continue
        tot["files"] += 1
        for k in tot:
            if k != "files":
                tot[k] += st[k]
        print(f"  [{i}/{len(files)}] {os.path.basename(fp)}: 生成 {st['ok']} "
              f"(重复 {st['dup']}, 重命名 {st['renamed']}, 无sha {st['no_sha']}, "
              f"跳过 {st['bad'] + st['empty']}, 写失败 {st['werr']})")

    if zip_mode:
        out_zip.close()
    conn.close()
    dt = time.time() - t0
    print(f"\n汇总: {tot['files']}/{len(files)} 个JSON成功, 生成 {tot['ok']} 个 CAS "
          f"(重复去重 {tot['dup']}, 同名重命名 {tot['renamed']}, 无sha {tot['no_sha']}, "
          f"无效 {tot['bad'] + tot['empty']}, 写失败 {tot['werr']})")
    print(f"耗时 {dt:.1f}s -> {out}")
    print(f"去重库: {db_path}")
    print("提示: cas139_check.py 批量检测命中率; SQL去重示例: SELECT sha256,COUNT(*) FROM cas GROUP BY sha256 HAVING COUNT(*)>1")


if __name__ == "__main__":
    main()
