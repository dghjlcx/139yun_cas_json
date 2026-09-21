#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
移动云盘(139) CAS 生成器
 - 单遍流式计算整文件 SHA256 (139 秒传只认这个, 无切片聚合, 比天翼简单)
 - 输出字段顺序与 CASX 样本一致: name/size/md5/sliceMd5/sha256/recover_pass/create_time
 - 生成 <文件>.cas (Base64 紧凑JSON), 可用 cas139_check.py 检测/恢复

用法:
  python cas139_gen.py 文件路径           本地模式: 单文件
  python cas139_gen.py 文件夹 [-r]        本地模式: 批量(加 -r 含子目录)
  python cas139_gen.py --cloud [云端目录ID=/] [输出目录=./cas_out] [-r]
                                        云端模式: 抓网盘 contentHash 生成 CAS, 零下载
                                        (凭证填在 cas139_check.py 顶部)
  不带参数运行 -> 交互式询问
"""
import base64
import hashlib
import json
import os
import sys
import time

CHUNK = 8 * 1024 * 1024
PROGRESS_EVERY = 512 * 1024 * 1024   # 每 512MB 打一次进度


def encode_cas139(name, size, sha256, create_time=None):
    payload = {
        "name": name,
        "size": size,
        "md5": "",
        "sliceMd5": "",
        "sha256": sha256,
        "recover_pass": "",
        "create_time": create_time or str(int(time.time())),
    }
    js = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(js.encode()).decode()


def hash_file(path, progress=False):
    """单遍流式 SHA256"""
    h = hashlib.sha256()
    size = 0
    next_mark = PROGRESS_EVERY
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
            if progress and size >= next_mark:
                print(f"    ... {size / 1024**3:.1f} GB", flush=True)
                next_mark += PROGRESS_EVERY
    return h.hexdigest(), size


def gen_one(path):
    name = os.path.basename(path)
    print(f"  [哈希] {name} ...", flush=True)
    t0 = time.perf_counter()
    sha256, size = hash_file(path, progress=True)
    dt = time.perf_counter() - t0
    cas = encode_cas139(name, size, sha256)
    with open(path + ".cas", "w", encoding="ascii") as f:
        f.write(cas)
    speed = size / 1024**2 / dt if dt else 0
    print(f"  [OK] {path}.cas  ({size:,} B, sha256={sha256[:16]}..., "
          f"{dt:.1f}s, {speed:.0f} MB/s)")
    return {"path": path, "size": size, "sha256": sha256, "seconds": round(dt, 2)}


def collect_files(path, recursive):
    if os.path.isfile(path):
        return [path] if not path.lower().endswith(".cas") else []
    if not os.path.isdir(path):
        return []
    out = []
    if recursive:
        for root, _, names in os.walk(path):
            out += [os.path.join(root, n) for n in names if not n.lower().endswith(".cas")]
    else:
        out = [os.path.join(path, n) for n in os.listdir(path)
               if os.path.isfile(os.path.join(path, n)) and not n.lower().endswith(".cas")]
    return out


# ============================================================
# 云端模式: 文件已在 139 网盘 -> 直接抓 contentHash 生成 CAS (零下载)
# 凭证配置在 cas139_check.py 顶部 (ACCOUNT+PASSWORD 或 AUTH_139)
# ============================================================
import re as _re

_ILLEGAL = _re.compile(r'[\\/:*?"<>|]')


def _sanitize(name):
    return _ILLEGAL.sub("_", name)


def cloud_mode(cloud_root="/", out_dir="./cas_out", recursive=False):
    try:
        from cas139_check import (ensure_auth, get_personal_host, cloud_request,
                                  PERSONAL_HEADERS, Cas139Error)
    except ImportError:
        print("[×] 需要 cas139_check.py 在同一目录 (云端模式复用其凭证与签名)")
        return

    print(f"[云端] 目标目录 {cloud_root} -> 输出到 {out_dir}"
          f"{' (递归)' if recursive else ' (仅当前层)'}")
    auth = ensure_auth()
    host = get_personal_host(auth)
    os.makedirs(out_dir, exist_ok=True)
    stats = {"gen": 0, "skip": 0, "folder": 0}

    def walk(folder_id, rel):
        page = 1
        while True:
            resp = cloud_request(host + "/file/list", {
                "parentFileId": folder_id,
                "pageInfo": {"page": page, "pageSize": 200,
                             "sortField": "lastOpTime", "sortAsc": False},
            }, auth, PERSONAL_HEADERS)
            items = (resp.get("data") or {}).get("items") or []
            for it in items:
                name = it.get("name", "")
                if it.get("type") == "folder":
                    stats["folder"] += 1
                    if recursive:
                        walk(it["fileId"], os.path.join(rel, _sanitize(name)))
                    continue
                ch = (it.get("contentHash") or "").lower()
                if not ch or it.get("contentHashAlgorithm", "sha256") != "sha256":
                    stats["skip"] += 1
                    print(f"  [跳过] {rel}/{name}: 无 contentHash 或非 sha256")
                    continue
                local_dir = os.path.join(out_dir, rel)
                os.makedirs(local_dir, exist_ok=True)
                with open(os.path.join(local_dir, _sanitize(name) + ".cas"),
                          "w", encoding="ascii") as f:
                    f.write(encode_cas139(name, int(it["size"]), ch))
                stats["gen"] += 1
                print(f"  [OK] {rel}/{name}  ({int(it['size']):,} B, sha256={ch[:16]}...)")
            if len(items) < 200:
                break
            page += 1

    walk(cloud_root, "")
    print(f"\n云端生成完成: {stats['gen']} 个 CAS / 跳过 {stats['skip']} / 文件夹 {stats['folder']}")


def main():
    args = sys.argv[1:]
    if "--cloud" in args:
        args.remove("--cloud")
        recursive = False
        pos = []
        for a in args:
            if a in ("-r", "--recursive"):
                recursive = True
            else:
                pos.append(a.strip('"').strip("'"))
        cloud_root = pos[0] if pos else "/"
        out_dir = pos[1] if len(pos) > 1 else "./cas_out"
        try:
            cloud_mode(cloud_root, out_dir, recursive)
        except Exception as e:
            print(f"[×] {e}")
        return

    recursive = False
    paths = []
    for a in args:
        if a in ("-r", "--recursive"):
            recursive = True
        else:
            paths.append(a.strip('"').strip("'"))
    if not paths:
        print("=" * 50)
        print("移动云盘(139) CAS 生成器")
        print("=" * 50)
        try:
            path = input("\n[文件或文件夹路径] ").strip().strip('"').strip("'")
            if not path:
                return
            r = input("[包含子文件夹?] (y/n, 回车=n): ").strip().lower()
            recursive = r in ("y", "yes", "是")
        except (EOFError, KeyboardInterrupt):
            return
    else:
        path = paths[0]

    if not os.path.exists(path):
        print(f"[×] 路径不存在: {path}")
        return
    files = collect_files(path, recursive)
    if not files:
        print("[×] 没有可处理的文件")
        return
    print(f"\n共 {len(files)} 个文件:")
    t_all = time.perf_counter()
    results = []
    for f in files:
        try:
            results.append(gen_one(f))
        except Exception as e:
            print(f"  [×] {f}: {e}")
    ok = len(results)
    print(f"\n完成 {ok}/{len(files)}, 总耗时 {time.perf_counter()-t_all:.1f}s")
    print("提示: 用 cas139_check.py 检测/恢复 -> python cas139_check.py <某个.cas>")


if __name__ == "__main__":
    main()
