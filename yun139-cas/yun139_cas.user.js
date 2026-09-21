// ==UserScript==
// @name         移动云盘CAS生成/恢复工具
// @namespace    local.tycas
// @version      1.3.1
// @description  移动云盘网页端: 勾选目录树导出 .cas (SHA256) 打包ZIP; 或导入本地CAS/ZIP恢复到网盘指定目录 (配合 cas139_check.py)
// @match        https://yun.139.com/*
// @match        https://*.yun.139.com/*
// @connect      yun.139.com
// @connect      user-njs.yun.139.com
// @connect      personal-kd-njs.yun.139.com
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @run-at       document-idle
// ==/UserScript==

(function () {
  'use strict';
  console.log('[tycas] 脚本已加载');

  // ============================================================
// ==CORE-BEGIN== (纯函数区: 与 cas139_check.py 算法对齐, 可独立测试)
 // ============================================================

 // MD5 (RFC1321, K表由 sin 生成)
  function md5(str) {
    const K = [];
    for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
    const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
               5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
               4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
               6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
    const bytes = unescape(encodeURIComponent(str)); // UTF-8 字节串
    const msg = [];
    for (let i = 0; i < bytes.length; i++) msg.push(bytes.charCodeAt(i));
    const bitLen = bytes.length * 8;
    msg.push(0x80);
    while (msg.length % 64 !== 56) msg.push(0);
    for (let i = 0; i < 8; i++) msg.push((bitLen / Math.pow(2, 8 * i)) & 0xFF);

    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    const rol = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
    for (let blk = 0; blk < msg.length; blk += 64) {
      const M = [];
      for (let i = 0; i < 16; i++) M[i] = (msg[blk + i * 4] | (msg[blk + i * 4 + 1] << 8) | (msg[blk + i * 4 + 2] << 16) | (msg[blk + i * 4 + 3] << 24)) >>> 0;
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }
        F = (F + A + K[i] + M[g]) >>> 0;
        A = D; D = C; C = B;
        B = (B + rol(F, S[i])) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    const le = (x) => [x & 0xFF, (x >>> 8) & 0xFF, (x >>> 16) & 0xFF, (x >>> 24) & 0xFF];
    const out = [...le(a0), ...le(b0), ...le(c0), ...le(d0)];
    return out.map(b => b.toString(16).padStart(2, '0')).join('');
  }

 // mcloud-sign (对齐 cas139_check.py cal_sign: encodeURIComponent -> 逐字符排序 -> b64 -> 双层md5大写)
  function calSign(body, ts, randStr) {
    const enc = encodeURIComponent(body);
    const sorted = enc.split('').sort().join('');
    const b64 = btoa(sorted); // enc 为纯 ASCII, 直接 btoa
    return md5(md5(b64) + md5(ts + ':' + randStr)).toUpperCase();
  }

 // CAS 编码 (字段顺序与 CASX 生态逐字节兼容)
  function encodeCas(name, size, sha256, createTime) {
    const payload = {
      name: name, size: size, md5: "", sliceMd5: "",
      sha256: sha256, recover_pass: "",
      create_time: createTime || String(Math.floor(Date.now() / 1000)),
    };
    const js = JSON.stringify(payload);
    return btoa(unescape(encodeURIComponent(js)));
  }

 // 免压缩 ZIP (store) 生成器
  function makeZip(entries) {
    const enc = new TextEncoder();
    const crcTable = (() => {
      const t = new Uint32Array(256);
      for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
        t[n] = c >>> 0;
      }
      return t;
    })();
    const crc32 = (data) => {
      let c = 0xFFFFFFFF;
      for (let i = 0; i < data.length; i++) c = crcTable[(c ^ data[i]) & 0xFF] ^ (c >>> 8);
      return (c ^ 0xFFFFFFFF) >>> 0;
    };
    const parts = [], central = [];
    let offset = 0;
    const now = new Date();
    const dosTime = ((now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1)) & 0xFFFF;
    const dosDate = (((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate()) & 0xFFFF;
    for (const e of entries) {
      const nameB = enc.encode(e.name);
      const crc = crc32(e.data);
      const size = e.data.length;
      const lh = new DataView(new ArrayBuffer(30));
      lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true);
      lh.setUint16(6, 0x0800, true); // UTF-8 文件名
      lh.setUint16(8, 0, true); // store
      lh.setUint16(10, dosTime, true); lh.setUint16(12, dosDate, true);
      lh.setUint32(14, crc, true); lh.setUint32(18, size, true); lh.setUint32(22, size, true);
      lh.setUint16(26, nameB.length, true); lh.setUint16(28, 0, true);
      parts.push(new Uint8Array(lh.buffer), nameB, e.data);
      central.push({ nameB, crc, size, offset });
      offset += 30 + nameB.length + size;
    }
    const cdParts = [];
    let cdSize = 0;
    for (const c of central) {
      const ch = new DataView(new ArrayBuffer(46));
      ch.setUint32(0, 0x02014b50, true); ch.setUint16(4, 20, true); ch.setUint16(6, 20, true);
      ch.setUint16(8, 0x0800, true); ch.setUint16(10, 0, true);
      ch.setUint16(12, dosTime, true); ch.setUint16(14, dosDate, true);
      ch.setUint32(16, c.crc, true); ch.setUint32(20, c.size, true); ch.setUint32(24, c.size, true);
      ch.setUint16(28, c.nameB.length, true);
      ch.setUint32(42, c.offset, true);
      cdParts.push(new Uint8Array(ch.buffer), c.nameB);
      cdSize += 46 + c.nameB.length;
    }
    const end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true);
    end.setUint16(8, central.length, true); end.setUint16(10, central.length, true);
    end.setUint32(12, cdSize, true); end.setUint32(16, offset, true);
    parts.push(...cdParts, new Uint8Array(end.buffer));
    const total = parts.reduce((s, p) => s + p.length, 0);
    const out = new Uint8Array(total);
    let pos = 0;
    for (const p of parts) { out.set(p, pos); pos += p.length; }
    return out;
  }

  function matchExt(name, exts) {
    if (!exts.length) return true;
    const parts = String(name).split('.');
    return parts.length > 1 && exts.includes(parts.pop().toLowerCase());
  }

  // CAS解码 (兼容139的sha256 / 天翼的md5格式识别)
  function decodeCas139(b64) {
    const js = decodeURIComponent(escape(atob(String(b64).trim())));
    const d = JSON.parse(js);
    if (d.sha256) return { name: d.name, size: Number(d.size), hash: String(d.sha256).toLowerCase(), algo: 'SHA256' };
    if (d.md5) return { name: d.name, size: Number(d.size), hash: d.md5, sliceMd5: d.sliceMd5 || '', algo: 'TY189' };
    throw new Error('无可用哈希(sha256/md5均为空)');
  }
  // 139 分片声明 (>30GB用512MB, 否则100MB, 只声明前100片)
  function makePartInfos(size) {
    const partSize = (size / (1024 * 1024 * 1024)) > 30 ? 512 * 1024 * 1024 : 100 * 1024 * 1024;
    const n = Math.ceil(size / partSize);
    const out = [];
    for (let i = 0; i < Math.min(n, 100); i++) {
      out.push({ partNumber: i + 1, partSize: Math.min(partSize, size - i * partSize), parallelHashCtx: { partOffset: i * partSize } });
    }
    return out;
  }
  // 免压缩ZIP生成器已在上方 (makeZip); 这里是对应的读取器 (store + deflate)
  async function unzip(buf) {
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    let eocd = -1;
    for (let i = buf.length - 22; i >= 0; i--) {
      if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error('ZIP结尾标志(EOCD)未找到');
    const count = dv.getUint16(eocd + 10, true);
    let off = dv.getUint32(eocd + 16, true);
    const out = [];
    for (let i = 0; i < count; i++) {
      if (dv.getUint32(off, true) !== 0x02014b50) break;
      const method = dv.getUint16(off + 10, true);
      const csize = dv.getUint32(off + 20, true);
      const nlen = dv.getUint16(off + 28, true);
      const elen = dv.getUint16(off + 30, true);
      const clen = dv.getUint16(off + 32, true);
      const lho = dv.getUint32(off + 42, true);
      const flags = dv.getUint16(off + 8, true);
      const dec = new TextDecoder((flags & 0x800) ? 'utf-8' : 'gbk');   // 无UTF-8标志按GBK(国产压缩软件/资源管理器)
      const name = dec.decode(buf.subarray(off + 46, off + 46 + nlen));
      const lnlen = dv.getUint16(lho + 26, true);
      const lelen = dv.getUint16(lho + 28, true);
      const raw = buf.subarray(lho + 30 + lnlen + lelen, lho + 30 + lnlen + lelen + csize);
      let data;
      if (method === 0) data = new Uint8Array(raw);
      else if (method === 8) {
        const ds = new DecompressionStream('deflate-raw');
        data = new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(ds)).arrayBuffer());
      } else { off += 46 + nlen + elen + clen; continue; }
      out.push({ name, data });
      off += 46 + nlen + elen + clen;
    }
    return out;
  }
  // 增量 SHA-256 (Web Crypto 不支持流式; DataView优化版 + Worker多线程)
  const SHA256_K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  function sha256Init() {
    return { h: [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
             w: new Uint32Array(64), buf: new Uint8Array(64), bufLen: 0, len: 0 };
  }
  function sha256Block(ctx, view, off) {
    const w = ctx.w;
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4, false);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let i = 16; i < 64; i++) {
      const x = w[i-15], y = w[i-2];
      const s0 = (rotr(x,7) ^ rotr(x,18) ^ (x>>>3)) >>> 0;
      const s1 = (rotr(y,17) ^ rotr(y,19) ^ (y>>>10)) >>> 0;
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let a=ctx.h[0],b=ctx.h[1],c=ctx.h[2],d=ctx.h[3],e=ctx.h[4],f=ctx.h[5],g=ctx.h[6],h=ctx.h[7];
    for (let i = 0; i < 64; i++) {
      const S1 = (rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = (rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    ctx.h[0]=(ctx.h[0]+a)>>>0; ctx.h[1]=(ctx.h[1]+b)>>>0; ctx.h[2]=(ctx.h[2]+c)>>>0; ctx.h[3]=(ctx.h[3]+d)>>>0;
    ctx.h[4]=(ctx.h[4]+e)>>>0; ctx.h[5]=(ctx.h[5]+f)>>>0; ctx.h[6]=(ctx.h[6]+g)>>>0; ctx.h[7]=(ctx.h[7]+h)>>>0;
  }
  function sha256Update(ctx, data) {
    ctx.len += data.length;
    let off = 0;
    if (ctx.bufLen) {
      const take = Math.min(64 - ctx.bufLen, data.length);
      ctx.buf.set(data.subarray(0, take), ctx.bufLen);
      ctx.bufLen += take;
      off = take;
      if (ctx.bufLen === 64) {
        sha256Block(ctx, new DataView(ctx.buf.buffer), 0);
        ctx.bufLen = 0;
      }
    }
    if (off < data.length) {
      const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
      for (; off + 64 <= data.length; off += 64) sha256Block(ctx, view, off);
      if (off < data.length) {
        ctx.buf.set(data.subarray(off), 0);
        ctx.bufLen = data.length - off;
      }
    }
  }
  function sha256Final(ctx) {
    const bitLen = ctx.len * 8;
    const tail = new Uint8Array(72);
    tail[0] = 0x80;
    const padLen = (ctx.bufLen < 56) ? (56 - ctx.bufLen) : (120 - ctx.bufLen);
    const tv = new DataView(tail.buffer);
    tv.setUint32(padLen, Math.floor(bitLen / 4294967296), false);
    tv.setUint32(padLen + 4, bitLen >>> 0, false);
    const total = ctx.bufLen + padLen + 8;
    const merged = new Uint8Array(total);
    merged.set(ctx.buf.subarray(0, ctx.bufLen), 0);
    merged.set(tail.subarray(0, padLen + 8), ctx.bufLen);
    const mv = new DataView(merged.buffer);
    sha256Block(ctx, mv, 0);
    if (total > 64) sha256Block(ctx, mv, 64);
    return ctx.h.map((x) => ('00000000' + x.toString(16)).slice(-8)).join('');
  }
  // 按序流水线读取: 最多CONC个分片在途(内存封顶 CONC*CH), 保证哈希输入顺序
  async function* readChunked(file, chunkSize, conc) {
    let off = 0;
    const inflight = [];
    while (off < file.size || inflight.length) {
      while (off < file.size && inflight.length < conc) {
        const start = off;
        off = Math.min(off + chunkSize, file.size);
        inflight.push(file.slice(start, off).arrayBuffer());
      }
      const ab = await inflight[0];
      inflight.shift();
      yield ab;
    }
  }
  // Worker 源码: 与主线程同一套哈希函数, 文件对象 postMessage 传入, 多线程不卡页面
  function buildWorkerSrc() {
    const coreSrc = sha256Init.toString() + '\n' + sha256Block.toString() + '\n' +
      sha256Update.toString() + '\n' + sha256Final.toString() + '\n' +
      readChunked.toString() +
      '\nconst SHA256_K = ' + JSON.stringify(SHA256_K) + ';';
    return coreSrc + `
self.onmessage = async function (e) {
  const job = e.data;
  try {
    const ctx = sha256Init();
    let done = 0, last = 0;
    for await (const ab of readChunked(job.file, 32 * 1024 * 1024, 2)) {
      sha256Update(ctx, new Uint8Array(ab));
      done += ab.byteLength;
      const now = Date.now();
      if (now - last > 100) { last = now; self.postMessage({ id: job.id, type: 'progress', done: done, total: job.size }); }
    }
    self.postMessage({ id: job.id, type: 'done', sha: sha256Final(ctx) });
  } catch (err) {
    self.postMessage({ id: job.id, type: 'error', message: String(err && err.message || err) });
  }
};`;
  }
  let __hashWorker = null, __hashJobId = 0;
  function getHashWorker() {
    if (__hashWorker) return __hashWorker;
    const blob = new Blob([buildWorkerSrc()], { type: 'application/javascript' });
    const W = (typeof Worker !== 'undefined') ? Worker : (unsafeWindow && unsafeWindow.Worker);
    const url = URL.createObjectURL(blob);
    __hashWorker = new W(url);
    setTimeout(() => { try { URL.revokeObjectURL(url); } catch (e) {} }, 5000);
    return __hashWorker;
  }
  function hashInWorker(file, onProgress) {
    return new Promise((resolve, reject) => {
      const w = getHashWorker();
      const id = ++__hashJobId;
      const timer = setTimeout(() => { cleanup(); reject(new Error('Worker哈希超时')); }, 30 * 60 * 1000);
      const cleanup = () => { clearTimeout(timer); w.removeEventListener('message', onMsg); };
      const onMsg = (e) => {
        const d = e.data || {};
        if (d.id !== id) return;
        if (d.type === 'done') { cleanup(); resolve(d.sha); }
        else if (d.type === 'error') { cleanup(); reject(new Error(d.message)); }
        else if (d.type === 'progress' && onProgress) onProgress(d.total ? d.done / d.total : 1);
      };
      w.addEventListener('message', onMsg);
      w.postMessage({ id, file, size: file.size });
    });
  }
  // 统一入口: 优先 Worker(不卡页面), 失败降级主线程分片+让出
  async function hashFileSha256(file, onProgress) {
    try {
      return await hashInWorker(file, onProgress);
    } catch (e) {
      console.warn('[tycas] Worker哈希失败, 降级主线程:', e);
    }
    // 主线程降级: 32MBx2 流水线, 每片让出事件循环, 不卡死且内存封顶
    const ctx = sha256Init();
    let done = 0, lastUi = 0;
    for await (const ab of readChunked(file, 32 * 1024 * 1024, 2)) {
      sha256Update(ctx, new Uint8Array(ab));
      done += ab.byteLength;
      const now = Date.now();
      if (onProgress && now - lastUi > 150) { lastUi = now; onProgress(file.size ? done / file.size : 1); }
      await new Promise((r) => setTimeout(r, 0));
    }
    if (onProgress) onProgress(1);
    return sha256Final(ctx);
  }

  // 分享库JSON解析: 数组/JSONL均可; 返回 {items:[{name(仅文件名),size,hash,algo,segs(目录段)}], skipped, shortHash}
  function parseShareJson(text) {
    let arr;
    try {
      const d = JSON.parse(text);
      if (Array.isArray(d)) arr = d;
      else if (d && typeof d === 'object') {
        arr = Object.values(d).find((v) => Array.isArray(v)) || [d];
      } else arr = [];
    } catch (e) {
      arr = [];
      let invalid = 0;
      for (const line of String(text).split(/\r?\n/)) {
        const t = line.trim();
        if (t) { try { arr.push(JSON.parse(t)); } catch (e2) { invalid++; } }
      }
      if (!arr.length && invalid) throw new Error('无法解析 (' + invalid + ' 行无效)');
    }
    const items = [];
    let skipped = 0, shortHash = 0;
    for (const e of arr) {
      if (!e || typeof e !== 'object') { skipped++; continue; }
      const sha = String(e.sha256 || '').trim().toLowerCase();
      const size = Number(e.size) || 0;
      if (!/^[0-9a-f]{64}$/.test(sha) || /^0{64}$/.test(sha) || size <= 0) {
        skipped++;
        if (/^[0-9a-f]{32}$/.test(sha) || /^[0-9a-f]{40}$/.test(sha)) shortHash++;
        continue;
      }
      const norm = String(e.name || '').replace(/\\/g, '/');
      const parts = norm.split('/');
      const base = parts[parts.length - 1].trim();
      if (!base) { skipped++; continue; }
      items.push({ name: base, size: size, hash: sha, algo: 'SHA256',
                   segs: parts.slice(0, -1).filter((p) => p && p !== '.' && p !== '..') });
    }
    return { items: items, skipped: skipped, shortHash: shortHash };
  }

  // 目录结构: 求所有dir的公共前缀 (打包时多包一层根目录的场景)
  function commonDirPrefix(dirs) {
    const ds = dirs.filter(Boolean);
    if (!ds.length) return '';
    const split = ds.map((d) => d.split('/'));
    const pref = [];
    for (let i = 0; i < split[0].length; i++) {
      const seg = split[0][i];
      if (split.every((sp) => sp[i] === seg)) pref.push(seg); else break;
    }
    return pref.join('/');
  }
  // 批次导入后剥公共前缀 (dir恰等于前缀的归入根)
  function stripCommonPrefix(files) {
    const pref = commonDirPrefix(files.map((f) => f.noStrip ? '' : f.dir));
    if (!pref) return;
    for (const f of files) {
      if (!f.dir || f.noStrip) continue;
      if (f.dir === pref) f.dir = '';
      else if (f.dir.startsWith(pref + '/')) f.dir = f.dir.slice(pref.length + 1);
    }
  }

 // ==CORE-END==
  // ============================================================

  const ROUTE_URL = 'https://user-njs.yun.139.com/user/route/qryRoutePolicy';
  const STATIC_HEADERS = {
    'Accept': 'application/json, text/plain, */*',
    'Cms-Device': 'default',
    'mcloud-channel': '1000101',
    'mcloud-client': '10701',
    'mcloud-version': '7.14.0',
    'Origin': 'https://yun.139.com',
    'Referer': 'https://yun.139.com/w/',
    'x-DeviceInfo': '||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||',
    'x-huawei-channelSrc': '10000034',
    'x-inner-ntwk': '2',
    'x-m4c-caller': 'PC',
    'x-m4c-src': '10002',
    'x-SvcType': '1',
    'Inner-Hcy-Router-Https': '1',
  };
  const PERSONAL_HEADERS = {
    'Caller': 'web', 'Mcloud-Route': '001',
    'X-Yun-Api-Version': 'v1', 'X-Yun-App-Channel': '10000034',
    'X-Yun-Channel-Source': '10000034',
    'X-Yun-Client-Info': '||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||dW5kZWZpbmVk||',
    'X-Yun-Module-Type': '100', 'X-Yun-SvcType': '1',
  };

  let authToken = null;
  let apiHost = null;
  let treeLoaded = false;
  let rtreeLoaded = false;
  let pendingFiles = [];   // 恢复用: {name, data:Uint8Array}

  const escapeHtml = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const sanitize = (n) => String(n).replace(/[\\/:*?"<>|]/g, '_');
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // ---- 捕获 Authorization ----
  function tryCapture(url, name, value) {
    if (url && /yun\.139\.com/.test(url) && /^authorization$/i.test(name)) {
      authToken = String(value).replace(/^Basic\s+/i, '');
      refreshIdleStatus();
      if (!treeLoaded) { treeLoaded = true; setTimeout(() => loadTree('export'), 600); }
    }
  }
  try {
    const P = unsafeWindow.XMLHttpRequest.prototype;
    const oSet = P.setRequestHeader;
    P.setRequestHeader = function (k, v) {
      try { tryCapture(this.__url, k, v); } catch (e) {}
      return oSet.call(this, k, v);
    };
    const oOpen = P.open;
    P.open = function (m, u) { this.__url = u; return oOpen.apply(this, arguments); };
  } catch (e) { console.warn('[tycas] XHR挂钩失败(不影响使用):', e); }
  try {
    const of = unsafeWindow.fetch;
    if (of) unsafeWindow.fetch = function (input, init) {
      try {
        const url = typeof input === 'string' ? input : input.url;
        if (init && init.headers) {
          const h = init.headers;
          const get = (k) => (h instanceof Headers) ? h.get(k) : (h[k] || h[k.toLowerCase()]);
          const v = get('Authorization');
          if (v) tryCapture(url, 'Authorization', v);
        }
      } catch (e) {}
      return of.apply(this, arguments);
    };
  } catch (e) { console.warn('[tycas] fetch挂钩失败(不影响使用):', e); }

  // ---- 签名 API ----
  function fmtTs(d) {
    const p = (n) => String(n).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }
  function api(url, bodyObj, extraHeaders) {
    return new Promise((resolve, reject) => {
      const body = JSON.stringify(bodyObj);
      const ts = fmtTs(new Date());
      const rand = Array.from({ length: 16 }, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random() * 62)]).join('');
      GM_xmlhttpRequest({
        method: 'POST',
        url,
        headers: Object.assign({}, STATIC_HEADERS, extraHeaders || {}, {
          'Content-Type': 'application/json;charset=UTF-8',
          'Authorization': 'Basic ' + authToken,
          'Mcloud-Sign': ts + ',' + rand + ',' + calSign(body, ts, rand),
        }),
        data: body,
        onload: (r) => { try { resolve(JSON.parse(r.responseText)); } catch (e) { reject(new Error('响应非JSON: ' + r.responseText.slice(0, 200))); } },
        onerror: (e) => reject(new Error('网络错误: ' + (e.error || ''))),
      });
    });
  }

  async function ensureHost() {
    if (apiHost) return apiHost;
    const account = decodeURIComponent(escape(atob(authToken))).split(':')[1];
    const route = await api(ROUTE_URL, { userInfo: { userType: 1, accountType: 1, accountName: account }, modAddrType: 1 });
    const p = (route.data.routePolicyList || []).find((x) => x.modName === 'personal');
    if (!p) throw new Error('路由策略无 personal');
    apiHost = String(p.httpsUrl).replace(/\/$/, '');
    return apiHost;
  }

  async function listFolders(fid) {
    const host = await ensureHost();
    const out = [];
    let page = 1;
    while (true) {
      const resp = await api(host + '/file/list', {
        parentFileId: fid,
        pageInfo: { page, pageSize: 200, sortField: 'name', sortAsc: true },
      }, PERSONAL_HEADERS);
      if (resp.success === false) throw new Error(resp.code + ' ' + resp.message);
      const items = ((resp.data || {}).items) || [];
      for (const it of items) if (it.type === 'folder') out.push({ fileId: it.fileId, name: it.name });
      if (items.length < 200) break;
      page++;
      await sleep(120);
    }
    return out;
  }

  function makeNode(fid, name, depth, inputType) {
    const wrap = document.createElement('div');
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;gap:4px;padding:2px 4px;white-space:nowrap';
    row.style.paddingLeft = (depth * 16 + 4) + 'px';
    const exp = document.createElement('span');
    exp.className = 'tycas-exp';
    exp.textContent = '▸';
    exp.style.cssText = 'cursor:pointer;width:14px;color:#8b949e;user-select:none;flex:none;text-align:center';
    const cb = document.createElement('input');
    cb.type = inputType;
    if (inputType === 'radio') cb.name = 'tycas-target';
    cb.dataset.fid = fid;
    cb.dataset.name = name;
    cb.style.cssText = 'appearance:auto!important;-webkit-appearance:' + inputType + '!important;opacity:1!important;visibility:visible!important;width:13px!important;height:13px!important;margin:0!important;padding:0!important;display:inline-block!important;background:#fff!important;border:1px solid #8b949e!important;flex:none!important';
    const nm = document.createElement('span');
    nm.textContent = name;
    nm.title = name;
    nm.style.cssText = 'overflow:hidden;text-overflow:ellipsis';
    row.append(exp, cb, nm);
    const kids = document.createElement('div');
    kids.style.display = 'none';
    let loaded = false, open = false;
    exp.onclick = async () => {
      open = !open;
      exp.textContent = open ? '▾' : '▸';
      kids.style.display = open ? '' : 'none';
      if (open && !loaded) {
        loaded = true;
        kids.innerHTML = '<div style="color:#8b949e;padding-left:' + ((depth + 1) * 16 + 20) + 'px">加载中…</div>';
        try {
          const folders = await listFolders(fid);
          kids.innerHTML = '';
          if (!folders.length) {
            kids.innerHTML = '<div style="color:#484f58;padding-left:' + ((depth + 1) * 16 + 20) + 'px;font-size:11px">(无子文件夹)</div>';
            return;
          }
          for (const f of folders) kids.appendChild(makeNode(f.fileId, f.name, depth + 1, inputType));
        } catch (e) {
          kids.innerHTML = '<div style="color:#f85149;padding-left:' + ((depth + 1) * 16 + 20) + 'px">加载失败: ' + escapeHtml(e.message) + '</div>';
          loaded = false;
        }
      }
    };
    wrap.append(row, kids);
    return wrap;
  }

  async function loadTree(kind) {
    const id = kind === 'export' ? '#tycas-tree' : '#tycas-rtree';
    const tree = panel.querySelector(id);
    if (!authToken) {
      tree.innerHTML = '<div style="color:#8b949e;padding:4px">等待登录态… (在网盘里点任意文件夹)</div>';
      return;
    }
    tree.innerHTML = '<div style="color:#8b949e;padding:4px">加载目录树…</div>';
    try {
      await ensureHost();
      const root = makeNode('/', '全部 (根目录)', 0, kind === 'export' ? 'checkbox' : 'radio');
      if (kind === 'restore') root.querySelector('input').checked = true;
      tree.innerHTML = '';
      tree.appendChild(root);
      root.querySelector('.tycas-exp').click();
    } catch (e) {
      tree.innerHTML = '<div style="color:#f85149;padding:4px">目录树加载失败: ' + escapeHtml(e.message) + '</div>';
    }
  }

  // ---- UI ----
  const panel = document.createElement('div');
  panel.id = 'tycas-panel';
  panel.style.cssText = 'position:fixed;right:18px;bottom:18px;z-index:999999;background:#161b22;' +
    'border:1px solid #30363d;border-radius:10px;padding:12px 14px;color:#c9d1d9;' +
    'font:13px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;width:340px;box-shadow:0 4px 16px rgba(0,0,0,.4)';
  const st = document.createElement('style');
  st.id = 'tycas-style';
  st.textContent = '#tycas-panel input{appearance:auto!important;opacity:1!important;visibility:visible!important}' +
    '#tycas-panel button{appearance:auto!important;opacity:1!important;visibility:visible!important}' +
    '.tycas-tab{cursor:pointer;padding:3px 10px;border-radius:6px 6px 0 0;font-size:12px;color:#8b949e;border:1px solid #30363d;border-bottom:none}' +
    '.tycas-tab.active{color:#58a6ff;background:#0d1117}' +
    '#tycas-panel a{color:#58a6ff}';
  (document.head || document.documentElement).appendChild(st);

  panel.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
      <div>
        <span class="tycas-tab active" data-tab="export">导出 CAS</span>
        <span class="tycas-tab" data-tab="restore">恢复 CAS</span>
        <span class="tycas-tab" data-tab="local">本地生成</span>
      </div>
      <span id="tycas-collapse" title="缩小" style="cursor:pointer;color:#8b949e;font-size:15px;padding:0 5px;user-select:none">─</span>
    </div>

    <div id="tab-export">
      <div style="margin-bottom:4px;font-size:12px;color:#8b949e">勾选要导出的文件夹 (勾选=整个子树)
        <a href="#" id="tycas-refresh" style="font-size:11px;margin-left:6px">刷新</a></div>
      <div id="tycas-tree" style="max-height:190px;overflow:auto;border:1px solid #30363d;border-radius:6px;padding:2px;margin-bottom:6px;background:#0d1117;font-size:12px">
        <div style="color:#8b949e;padding:4px">等待登录态… (在网盘里点任意文件夹)</div>
      </div>
      <div style="margin-bottom:4px;font-size:12px;color:#8b949e">格式过滤 (逗号分隔, 留空=全部)</div>
      <input id="tycas-ext" type="text" placeholder="mkv,mp4,iso" style="width:100%;margin-bottom:8px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:5px;font-size:12px;box-sizing:border-box">
      <div style="margin-bottom:4px;font-size:12px;color:#8b949e">导出格式</div>
      <select id="tycas-exportfmt" style="width:100%;margin-bottom:8px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:5px;font-size:12px">
        <option value="cas">CAS 打包 (.cas ZIP, 可直接恢复)</option>
        <option value="json">分享库 JSON (.json, name为全路径, 可回流分享)</option>
      </select>
      <button id="tycas-btn" style="width:100%;padding:7px;border:none;border-radius:6px;cursor:pointer;background:#238636;color:#fff;font-size:13px">按勾选的文件夹导出</button>
    </div>

    <div id="tab-restore" style="display:none">
      <div style="margin-bottom:4px;font-size:12px;color:#8b949e">恢复到目录 (单选): <span style="color:#484f58">含目录的ZIP/文件夹自动重建子目录; 每个JSON以其文件名建文件夹</span></div>
      <div id="tycas-rtree" style="max-height:130px;overflow:auto;border:1px solid #30363d;border-radius:6px;padding:2px;margin-bottom:6px;background:#0d1117;font-size:12px">
        <div style="color:#8b949e;padding:4px">(切到本页签后加载)</div>
      </div>
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <button id="tycas-addfiles" style="flex:1;padding:6px;border:1px solid #30363d;border-radius:6px;cursor:pointer;background:#21262d;color:#c9d1d9;font-size:12px">添加 CAS/ZIP/JSON</button>
        <button id="tycas-addfolder" style="flex:1;padding:6px;border:1px solid #30363d;border-radius:6px;cursor:pointer;background:#21262d;color:#c9d1d9;font-size:12px">添加文件夹</button>
      </div>
      <input id="tycas-file" type="file" multiple accept=".cas,.zip,.json" style="display:none">
      <input id="tycas-dir" type="file" webkitdirectory style="display:none">
      <div style="margin-bottom:4px;font-size:12px;color:#8b949e">JSON 目录模式</div>
      <select id="tycas-jsonmode" style="width:100%;margin-bottom:6px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:5px;font-size:12px">
        <option value="jsonname">按JSON文件名建文件夹 (每部剧一个文件夹)</option>
        <option value="full">保留条目完整路径 (自动剥共同前缀)</option>
        <option value="tail1">保留末尾1级目录</option>
        <option value="tail2">保留末尾2级目录</option>
      </select>
      <label style="display:flex;align-items:center;gap:5px;margin-bottom:6px;cursor:pointer;font-size:12px;color:#8b949e">
        <input type="checkbox" id="tycas-striproot" checked> 剥掉ZIP/文件夹的最外层公共目录 (导出往返导入时请取消勾选)</label>
      <div id="tycas-filelist" style="max-height:70px;overflow:auto;font-size:11px;color:#8b949e;margin-bottom:6px;border:1px solid #21262d;border-radius:6px;padding:4px">(尚未添加文件)</div>
      <button id="tycas-restorebtn" style="width:100%;padding:7px;border:none;border-radius:6px;cursor:pointer;background:#1f6feb;color:#fff;font-size:13px">开始恢复到网盘</button>
      <div id="tycas-rlog" style="max-height:90px;overflow:auto;font-size:11px;margin-top:6px;color:#8b949e"></div>
    </div>

    <div id="tab-local" style="display:none">
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <button id="tycas-lfile" style="flex:1;padding:6px;border:1px solid #30363d;border-radius:6px;cursor:pointer;background:#21262d;color:#c9d1d9;font-size:12px">选择文件</button>
        <button id="tycas-ldir" style="flex:1;padding:6px;border:1px solid #30363d;border-radius:6px;cursor:pointer;background:#21262d;color:#c9d1d9;font-size:12px">选择文件夹</button>
        <button id="tycas-lout" style="flex:1;padding:6px;border:1px solid #30363d;border-radius:6px;cursor:pointer;background:#21262d;color:#c9d1d9;font-size:12px">输出目录…</button>
      </div>
      <div id="tycas-loutinfo" style="font-size:11px;color:#8b949e;margin-bottom:6px">输出: 打包 ZIP 下载 (选择输出目录可直接写入)</div>
      <label style="display:flex;align-items:center;gap:5px;margin-bottom:6px;cursor:pointer;font-size:12px;color:#8b949e">
        <input type="checkbox" id="tycas-lkeep" checked> 保持目录结构</label>
      <input id="tycas-lfileinput" type="file" multiple style="display:none">
      <input id="tycas-ldirinput" type="file" webkitdirectory style="display:none">
      <div id="tycas-llist" style="max-height:70px;overflow:auto;font-size:11px;color:#8b949e;margin-bottom:6px;border:1px solid #21262d;border-radius:6px;padding:4px">(尚未选择文件)</div>
      <button id="tycas-lbtn" style="width:100%;padding:7px;border:none;border-radius:6px;cursor:pointer;background:#8957e5;color:#fff;font-size:13px">开始生成 CAS</button>
      <div id="tycas-llog" style="max-height:90px;overflow:auto;font-size:11px;margin-top:6px;color:#8b949e"></div>
    </div>

    <div id="tycas-status" style="margin-top:8px;font-size:12px;color:#8b949e;white-space:pre-wrap">等待捕获登录态… (在网盘里点任意文件夹)</div>`;

  const mini = document.createElement('div');
  mini.id = 'tycas-mini';
  mini.textContent = '📦';
  mini.title = 'CAS 工具';
  mini.style.cssText = 'position:fixed;right:18px;bottom:18px;z-index:999999;width:42px;height:42px;border-radius:50%;background:#161b22;border:1px solid #30363d;display:none;align-items:center;justify-content:center;cursor:pointer;font-size:19px;box-shadow:0 4px 16px rgba(0,0,0,.4);user-select:none';
  function setCollapsed(c) {
    panel.style.display = c ? 'none' : '';
    mini.style.display = c ? 'flex' : 'none';
    try { localStorage.setItem('tycas-collapsed', c ? '1' : '0'); } catch (e) {}
  }
  function mount() {
    document.body.appendChild(panel);
    document.body.appendChild(mini);
    panel.querySelector('#tycas-collapse').addEventListener('click', () => setCollapsed(true));
    mini.addEventListener('click', () => setCollapsed(false));
    try { if (localStorage.getItem('tycas-collapsed') === '1') setCollapsed(true); } catch (e) {}
  }
  if (document.body) mount();
  else document.addEventListener('DOMContentLoaded', mount);

  const $status = panel.querySelector('#tycas-status');
  const $rlog = panel.querySelector('#tycas-rlog');

  function refreshIdleStatus() {
    if ($status.dataset.busy) return;
    $status.textContent = authToken ? '已捕获登录态 ✓' : '等待捕获登录态… (在网盘里点任意文件夹)';
  }

  // ---- Tab 切换 ----
  panel.querySelectorAll('.tycas-tab').forEach((t) => {
    t.addEventListener('click', () => {
      panel.querySelectorAll('.tycas-tab').forEach((x) => x.classList.remove('active'));
      t.classList.add('active');
      const kind = t.dataset.tab;
      ['export', 'restore', 'local'].forEach((k) => {
        panel.querySelector('#tab-' + k).style.display = kind === k ? '' : 'none';
      });
      if (kind === 'restore' && !rtreeLoaded) { rtreeLoaded = true; loadTree('restore'); }
    });
  });
  panel.querySelector('#tycas-refresh').addEventListener('click', (e) => { e.preventDefault(); loadTree('export'); });

  function downloadZip(entries, prefix) {
    const zip = makeZip(entries);
    const blob = new Blob([zip], { type: 'application/zip' });
    const a = document.createElement('a');
    const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
    a.href = URL.createObjectURL(blob);
    a.download = prefix + stamp + '.zip';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
  }

  // ---- 导出 ----
  async function doExport() {
    if (!authToken) { $status.textContent = '尚未捕获 Authorization, 请先在网盘页面点一个文件夹'; return; }
    const checkedEls = [...panel.querySelectorAll('#tycas-tree input[data-fid]:checked')];
    if (!checkedEls.length) { $status.textContent = '请先在目录树里勾选至少一个文件夹'; return; }
    const fmt = ((panel.querySelector('#tycas-exportfmt') || {}).value) || 'cas';
    const exts = (panel.querySelector('#tycas-ext').value || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
    const seen = {};
    const queue = checkedEls.map((el) => {
      let base = el.dataset.fid === '/' ? '根目录' : (sanitize(el.dataset.name) || 'folder');
      if (seen[base] !== undefined) { seen[base]++; base = base + '_' + seen[base]; } else seen[base] = 0;
      return { id: el.dataset.fid, path: base + '/' };
    });
    const btn = panel.querySelector('#tycas-btn');
    btn.disabled = true;
    $status.dataset.busy = '1';
    const t0 = Date.now();
    const stats = { gen: 0, skip: 0, filtered: 0, folder: 0, page: 0 };
    const results = [];
    const walked = new Set();
    try {
      while (queue.length) {
        const cur = queue.shift();
        if (walked.has(cur.id)) continue;
        walked.add(cur.id);
        let page = 1;
        while (true) {
          const resp = await api(apiHost + '/file/list', {
            parentFileId: cur.id,
            pageInfo: { page, pageSize: 200, sortField: 'lastOpTime', sortAsc: false },
          }, PERSONAL_HEADERS);
          if (resp.success === false) throw new Error('列表失败: ' + resp.code + ' ' + resp.message);
          const items = ((resp.data || {}).items) || [];
          stats.page++;
          for (const it of items) {
            if (it.type === 'folder') {
              stats.folder++;
              queue.push({ id: it.fileId, path: cur.path + sanitize(it.name) + '/' });
              continue;
            }
            if (!matchExt(it.name, exts)) { stats.filtered++; continue; }
            const ch = (it.contentHash || '').toLowerCase();
            if (ch && (it.contentHashAlgorithm || 'sha256') === 'sha256') {
              results.push({ rel: cur.path + sanitize(it.name) + '.cas', path: cur.path,
                             name: it.name, size: Number(it.size), sha: ch });
              stats.gen++;
            } else stats.skip++;
          }
          $status.textContent = '遍历中… 目录' + stats.folder + ' 文件' + stats.gen + ' 过滤' + stats.filtered + ' 跳过' + stats.skip + '\n已扫描 ' + stats.page + ' 页';
          if (items.length < 200) break;
          page++;
          await sleep(150);
        }
        await sleep(150);
      }
      if (!results.length) {
        delete $status.dataset.busy;
        $status.textContent = '完成, 没有可生成的文件 (过滤' + stats.filtered + ', 跳过' + stats.skip + ')';
        btn.disabled = false;
        return;
      }
      if (fmt === 'json') {
        $status.textContent = '生成分享库 JSON (' + results.length + ' 条)…';
        const entries = results.map((r) => ({ name: r.path + r.name, size: r.size, sha256: r.sha }));
        const blob = new Blob([JSON.stringify(entries, null, 1)], { type: 'application/json' });
        const a = document.createElement('a');
        const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
        a.href = URL.createObjectURL(blob);
        a.download = '139_share_' + stamp + '.json';
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 10000);
        $status.textContent = '✅ 完成! ' + stats.gen + ' 条分享记录 (过滤' + stats.filtered + ', 跳过' + stats.skip + ', 文件夹' + stats.folder + ')\n' +
          '耗时 ' + ((Date.now() - t0) / 1000).toFixed(1) + 's, JSON 已开始下载 (可用"保留完整路径"模式导回)';
      } else {
        $status.textContent = '生成 ZIP (' + results.length + ' 个CAS)…';
        const enc = new TextEncoder();
        const entries = results.map((r) => ({ name: r.rel, data: enc.encode(encodeCas(r.name, r.size, r.sha)) }));
        downloadZip(entries, '139_cas_');
        $status.textContent = '✅ 完成! ' + stats.gen + ' 个 CAS (过滤' + stats.filtered + ', 跳过' + stats.skip + ', 文件夹' + stats.folder + ')\n' +
          '耗时 ' + ((Date.now() - t0) / 1000).toFixed(1) + 's, ZIP 已开始下载';
      }
    } catch (e) {
      $status.textContent = '❌ ' + e.message;
    }
    delete $status.dataset.busy;
    btn.disabled = false;
  }
  panel.querySelector('#tycas-btn').addEventListener('click', doExport);

  // ---- 恢复 ----
  function updateFileList() {
    const el = panel.querySelector('#tycas-filelist');
    if (!pendingFiles.length) { el.textContent = '(尚未添加文件)'; return; }
    el.innerHTML = pendingFiles.map((f, i) =>
      '<div>' + (i + 1) + '. ' + (f.dir ? '<span style="color:#484f58">' + escapeHtml(f.dir) + '/</span>' : '') +
      escapeHtml(f.name) + ' <a href="#" data-i="' + i + '" class="tycas-rm" style="color:#f85149;font-size:10px">移除</a></div>').join('');
    el.querySelectorAll('.tycas-rm').forEach((a) => a.addEventListener('click', (e) => {
      e.preventDefault();
      pendingFiles.splice(Number(a.dataset.i), 1);
      updateFileList();
    }));
  }

  async function addFiles(fileList) {
    let added = 0;
    for (const f of fileList) {
      const lower = f.name.toLowerCase();
      try {
        if (lower.endsWith('.zip')) {
          const entries = await unzip(new Uint8Array(await f.arrayBuffer()));
          for (const e of entries) {
            if (e.name.toLowerCase().endsWith('.cas')) {
              const norm = e.name.replace(/\\/g, '/');     // 国产压缩软件可能用反斜杠存路径
              const dirPart = norm.includes('/') ? norm.slice(0, norm.lastIndexOf('/')) : '';
              pendingFiles.push({ name: norm.split('/').pop(), dir: dirPart, data: e.data });
              added++;
            }
          }
        } else if (lower.endsWith('.cas')) {
          const rel = f.webkitRelativePath || '';
          const dirPart = rel.includes('/') ? rel.split('/').slice(1, -1).join('/') : '';
          pendingFiles.push({ name: f.name, dir: dirPart, data: new Uint8Array(await f.arrayBuffer()) });
          added++;
        } else if (lower.endsWith('.json')) {
          const mode = ((panel.querySelector('#tycas-jsonmode') || {}).value) || 'jsonname';
          const jsonDir = f.name.replace(/\.json$/i, '');
          const r = parseShareJson(await f.text());
          for (const it of r.items) {
            let d = jsonDir, noStrip = true;
            if (mode === 'full') { d = it.segs.join('/'); noStrip = false; }
            else if (mode === 'tail1') d = it.segs.slice(-1).join('/');
            else if (mode === 'tail2') d = it.segs.slice(-2).join('/');
            pendingFiles.push({ name: it.name, dir: d, noStrip: noStrip, info: it });
            added++;
          }
          if (!r.items.length) {
            $status.textContent = '⚠ ' + f.name + ': 0 条可用' +
              (r.shortHash ? ' — ' + r.shortHash + ' 条是32/40位短哈希(截断/MD5), 139秒传需要完整64位SHA256' : ' — 记录无效或缺少sha256');
          } else if (r.skipped) {
            $status.textContent = f.name + ': 导入 ' + r.items.length + ' 条, 跳过 ' + r.skipped + ' 条无效';
          }
        }
      } catch (e) {
        $status.textContent = '❌ 读取 ' + f.name + ' 失败: ' + e.message;
      }
    }
    if (panel.querySelector('#tycas-striproot').checked) stripCommonPrefix(pendingFiles);
    updateFileList();
    if (added > 0) $status.textContent = '已添加 ' + pendingFiles.length + ' 个文件 (含目录结构)';
  }
  panel.querySelector('#tycas-addfiles').addEventListener('click', () => panel.querySelector('#tycas-file').click());
  panel.querySelector('#tycas-addfolder').addEventListener('click', () => panel.querySelector('#tycas-dir').click());
  panel.querySelector('#tycas-file').addEventListener('change', (e) => { addFiles(e.target.files); e.target.value = ''; });
  panel.querySelector('#tycas-dir').addEventListener('change', (e) => { addFiles(e.target.files); e.target.value = ''; });

  async function doRestore() {
    if (!authToken) { $status.textContent = '尚未捕获 Authorization'; return; }
    if (!pendingFiles.length) { $status.textContent = '请先添加 CAS/ZIP 文件'; return; }
    const sel = panel.querySelector('input[name=tycas-target]:checked');
    const target = sel ? sel.dataset.fid : '/';
    const btn = panel.querySelector('#tycas-restorebtn');
    btn.disabled = true;
    $status.dataset.busy = '1';
    $rlog.innerHTML = '';
    const log = (msg, color) => {
      const d = document.createElement('div');
      if (color) d.style.color = color;
      d.textContent = msg;
      $rlog.appendChild(d);
      $rlog.scrollTop = $rlog.scrollHeight;
    };
    let ok = 0, exist = 0, miss = 0, fail = 0;
    const folderCache = new Map();
    async function resolveDir(dir) {
      if (!dir) return target;
      let cur = target;
      for (const part of dir.split('/')) {
        const name = part.replace(/[. ]+$/, '') || '文件夹';
        const key = cur + '/' + name;
        if (folderCache.has(key)) { cur = folderCache.get(key); continue; }
        const resp = await api(apiHost + '/file/create', {
          parentFileId: cur, name: name, type: 'folder',
        }, PERSONAL_HEADERS);
        if (resp.success === false) throw new Error('建目录[' + name + ']失败: ' + resp.code + ' ' + resp.message);
        const fid = (resp.data || {}).fileId;
        if (!fid) throw new Error('建目录[' + name + ']响应缺fileId');
        folderCache.set(key, fid);
        cur = fid;
        await sleep(300);
      }
      return cur;
    }
    try {
      await ensureHost();
      const total = pendingFiles.length;
      for (let i = 0; i < total; i++) {
        const f = pendingFiles[i];
        let info;
        try {
          info = f.info || decodeCas139(new TextDecoder().decode(f.data));
        } catch (e) {
          fail++;
          log('✗ ' + f.name + ': 解析失败 ' + e.message, '#f85149');
          continue;
        }
        if (!info.hash || !/^[0-9a-f]{64}$/.test(info.hash) || /^0{64}$/.test(info.hash)) {
          fail++;
          log('✗ ' + info.name + ': 哈希无效(空/格式错/全零占位), 已跳过', '#f85149');
          continue;
        }
        if (info.algo === 'TY189') {
          fail++;
          log('✗ ' + f.name + ': 天翼格式(md5), 请用 cas139_check.py 恢复', '#d29922');
          continue;
        }
        $status.textContent = '恢复中 ' + (i + 1) + '/' + total + '  ' + info.name;
        try {
          const parentId = await resolveDir(f.dir || '');
          const resp = await api(apiHost + '/file/create', {
            contentHash: info.hash,
            contentHashAlgorithm: 'SHA256',
            contentType: 'application/octet-stream',
            parallelUpload: false,
            partInfos: makePartInfos(info.size),
            size: info.size,
            parentFileId: parentId,
            name: info.name,
            type: 'file',
            fileRenameMode: 'auto_rename',
          }, PERSONAL_HEADERS);
          if (resp.success === false) {
            fail++;
            log('✗ ' + info.name + ': ' + resp.code + ' ' + resp.message +
                ' [hash=' + info.hash.slice(0, 16) + '… size=' + info.size + ']', '#f85149');
          } else {
            const d = resp.data || {};
            const loc = f.dir ? '[' + f.dir + '/] ' : '';
            if (d.exist) { exist++; log('= ' + loc + info.name + ': 已存在同名', '#d29922'); }
            else if (d.rapidUpload && !d.partInfos) { ok++; log('✓ ' + loc + info.name + ' (fileId=' + d.fileId + ')', '#3fb950'); }
            else if (d.partInfos) { miss++; log('✗ ' + loc + info.name + ': 数据不在云端', '#f85149'); }
            else { fail++; log('? ' + loc + info.name + ': 未知响应', '#d29922'); }
          }
        } catch (e) {
          fail++;
          log('✗ ' + info.name + ': ' + e.message, '#f85149');
        }
        await sleep(300);
      }
      $status.textContent = '✅ 恢复完成: 成功 ' + ok + ' / 已存在 ' + exist + ' / 未命中 ' + miss + ' / 失败 ' + fail;
    } catch (e) {
      $status.textContent = '❌ ' + e.message;
    }
    delete $status.dataset.busy;
    btn.disabled = false;
  }
  panel.querySelector('#tycas-restorebtn').addEventListener('click', doRestore);

  // ---- 本地生成 ----
  let localFiles = [];      // {file: File, rel: 'dir/name'}
  let outDirHandle = null;
  const hasFSAPI = typeof showDirectoryPicker === 'function';

  async function walkDirHandle(dirHandle, path, out) {
    for await (const entry of dirHandle.values()) {
      if (entry.kind === 'file') {
        if (!entry.name.toLowerCase().endsWith('.cas')) {
          out.push({ file: await entry.getFile(), rel: path + entry.name });
        }
      } else if (entry.kind === 'directory') {
        await walkDirHandle(entry, path + entry.name + '/', out);
      }
    }
  }

  async function writeCasTo(outDir, relPath, content) {
    const parts = String(relPath).split('/');
    let cur = outDir;
    for (const part of parts.slice(0, -1)) cur = await cur.getDirectoryHandle(part, { create: true });
    const fh = await cur.getFileHandle(parts[parts.length - 1], { create: true });
    const w = await fh.createWritable();
    await w.write(content);
    await w.close();
  }

  function updateLocalList() {
    const el = panel.querySelector('#tycas-llist');
    if (!localFiles.length) { el.textContent = '(尚未选择文件)'; return; }
    el.innerHTML = localFiles.map((f, i) =>
      '<div>' + (i + 1) + '. ' + escapeHtml(f.rel) + ' <a href="#" data-i="' + i + '" class="tycas-lrm" style="color:#f85149;font-size:10px">移除</a></div>').join('');
    el.querySelectorAll('.tycas-lrm').forEach((a) => a.addEventListener('click', (e) => {
      e.preventDefault();
      localFiles.splice(Number(a.dataset.i), 1);
      updateLocalList();
    }));
  }

  // 来源: FS API (Chrome/Edge) 或 input 回退
  panel.querySelector('#tycas-lfile').addEventListener('click', async () => {
    if (hasFSAPI && window.showOpenFilePicker) {
      try {
        const handles = await window.showOpenFilePicker({ multiple: true });
        for (const h of handles) {
          const f = await h.getFile();
          localFiles.push({ file: f, rel: f.name });
        }
        updateLocalList();
        return;
      } catch (e) { if (e && e.name === 'AbortError') return; console.warn('[tycas] FS API失败, 回退input:', e); }
    }
    panel.querySelector('#tycas-lfileinput').click();
  });
  panel.querySelector('#tycas-ldir').addEventListener('click', async () => {
    if (hasFSAPI) {
      try {
        const dir = await window.showDirectoryPicker();
        const found = [];
        await walkDirHandle(dir, '', found);
        localFiles.push(...found);
        updateLocalList();
        return;
      } catch (e) { if (e && e.name === 'AbortError') return; console.warn('[tycas] FS API失败, 回退input:', e); }
    }
    panel.querySelector('#tycas-ldirinput').click();
  });
  panel.querySelector('#tycas-lfileinput').addEventListener('change', (e) => {
    for (const f of e.target.files) localFiles.push({ file: f, rel: f.name });
    e.target.value = '';
    updateLocalList();
  });
  panel.querySelector('#tycas-ldirinput').addEventListener('change', (e) => {
    for (const f of e.target.files) {
      const rel = f.webkitRelativePath || f.name;
      const ln = f.name.toLowerCase();
      if (ln.endsWith('.cas') || ln.endsWith('.zip') || ln.endsWith('.json')) continue;
      localFiles.push({ file: f, rel });
    }
    e.target.value = '';
    updateLocalList();
  });
  panel.querySelector('#tycas-lout').addEventListener('click', async () => {
    if (!hasFSAPI) { $status.textContent = '当前浏览器不支持直写目录, 结果将打包ZIP下载'; return; }
    try {
      outDirHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
      panel.querySelector('#tycas-loutinfo').textContent = '输出目录: ' + outDirHandle.name + ' (CAS 将直接写入, 保持结构)';
    } catch (e) { if (e && e.name !== 'AbortError') $status.textContent = '选择输出目录失败: ' + e.message; }
  });
  if (!hasFSAPI) {
    panel.querySelector('#tycas-loutinfo').textContent = '输出: 打包 ZIP 下载 (此浏览器不支持直写目录; 解压后即与原目录同结构)';
  }

  async function doLocalGen() {
    if (!localFiles.length) { $status.textContent = '请先选择本地文件或文件夹'; return; }
    const keep = panel.querySelector('#tycas-lkeep').checked;
    const btn = panel.querySelector('#tycas-lbtn');
    const $llog = panel.querySelector('#tycas-llog');
    btn.disabled = true;
    $status.dataset.busy = '1';
    $llog.innerHTML = '';
    const log = (msg, color) => {
      const d = document.createElement('div');
      if (color) d.style.color = color;
      d.textContent = msg;
      $llog.appendChild(d);
      $llog.scrollTop = $llog.scrollHeight;
    };
    const enc = new TextEncoder();
    const zipEntries = [];
    const t0 = Date.now();
    let okN = 0, failN = 0;
    try {
      const total = localFiles.length;
      for (let i = 0; i < total; i++) {
        const lf = localFiles[i];
        $status.textContent = '哈希中 ' + (i + 1) + '/' + total + '  ' + lf.rel +
          '\n(只读本地文件计算SHA256, 不上传任何数据)';
        let sha;
        try {
          sha = await hashFileSha256(lf.file, (p) => {
            $status.textContent = '哈希中 ' + (i + 1) + '/' + total + '  ' + lf.rel + '  ' + Math.round(p * 100) + '%';
          });
        } catch (e) {
          failN++;
          log('✗ ' + lf.rel + ': ' + e.message, '#f85149');
          continue;
        }
        const baseRel = keep ? lf.rel : lf.file.name;
        const casRel = baseRel.split('/').map(sanitize).join('/') + '.cas';
        const content = encodeCas(lf.file.name, lf.file.size, sha);
        if (outDirHandle) {
          try {
            await writeCasTo(outDirHandle, casRel, content);
          } catch (e) {
            failN++;
            log('✗ ' + lf.rel + ': 写入失败 ' + e.message, '#f85149');
            continue;
          }
        } else {
          zipEntries.push({ name: casRel, data: enc.encode(content) });
        }
        okN++;
        log('✓ ' + lf.rel + '  sha256=' + sha.slice(0, 16) + '…', '#3fb950');
        lf.file = null;   // 释放文件引用, 让浏览器回收内存
      }
      if (!outDirHandle && zipEntries.length) downloadZip(zipEntries, '139_cas_local_');
      localFiles.forEach((lf) => { lf.file = null; });   // 全部释放
      updateLocalList();
      $status.textContent = '✅ 本地生成完成: 成功 ' + okN + ' / 失败 ' + failN +
        (outDirHandle ? ' (已写入目录 ' + outDirHandle.name + ')' : ' (ZIP 已开始下载)') +
        '\n耗时 ' + ((Date.now() - t0) / 1000).toFixed(1) + 's, 文件引用已释放';
    } catch (e) {
      $status.textContent = '❌ ' + e.message;
    }
    delete $status.dataset.busy;
    btn.disabled = false;
  }
  panel.querySelector('#tycas-lbtn').addEventListener('click', doLocalGen);
})();
