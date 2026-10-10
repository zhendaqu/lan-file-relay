#!/usr/bin/env python3
"""
局域网中转站：网页剪贴板 + 拖拽文件中转。

单文件、零依赖，直接运行：

    python3 share.py            # 默认 8000 端口
    PORT=9000 python3 share.py  # 换端口

终端会打印局域网地址，同一个 Wi-Fi 下的手机/电脑打开同一个地址，
就能互相粘贴文本、互传文件。数据保存在脚本旁边的 share_data/ 目录。

几个实现要点：
  * 上传：流式落盘，顺带算出 SHA-256 / MD5，页面上点校验值可查看复制
  * 下载：支持 Range / If-Range / ETag，断点续传（curl -C -、下载工具、浏览器都认）
  * 无鉴权：同一网段谁打开地址都能读写，只适合可信的局域网
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import signal
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse

# ---------------------------------------------------------------- 配置

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("SHARE_DATA") or os.path.join(HERE, "share_data")
FILES_DIR = os.path.join(DATA_DIR, "files")
STATE_FILE = os.path.join(DATA_DIR, "state.json")

PORT = int(os.environ.get("PORT", "8000"))
HOST = os.environ.get("HOST", "0.0.0.0")
MAX_SNIPPET = 200_000                 # 单条文本上限
MAX_UPLOAD = 4 * 1024 * 1024 * 1024   # 单文件上限 4GB

os.makedirs(FILES_DIR, exist_ok=True)

LOCK = threading.Lock()
STATE: dict = {"snippets": [], "files": []}


def load_state() -> None:
    global STATE
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        STATE["snippets"] = [s for s in data.get("snippets", []) if isinstance(s, dict)]
        STATE["files"] = [f for f in data.get("files", []) if isinstance(f, dict)]
        # 丢掉磁盘上已经不存在的记录
        STATE["files"] = [f for f in STATE["files"] if os.path.exists(file_path(f["id"]))]
    except (OSError, ValueError):
        pass


def save_state() -> None:
    tmp = STATE_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fp:
            json.dump(STATE, fp, ensure_ascii=False)
        os.replace(tmp, STATE_FILE)
    except OSError:
        pass


def file_path(fid: str) -> str:
    return os.path.join(FILES_DIR, fid)


def hashers():
    """一对增量 hash 对象，边收边算，不用二次读盘。"""
    try:
        md5 = hashlib.md5(usedforsecurity=False)
    except (TypeError, ValueError):
        md5 = hashlib.md5()
    return hashlib.sha256(), md5


def fill_missing_hashes() -> None:
    """老记录（升级前上传的）没有校验值，启动后在后台补算，不挡轮询。"""
    todo = [f for f in STATE["files"] if not f.get("sha256")]
    if not todo:
        return
    done = 0
    for item in todo:
        try:
            sha, md5 = hashers()
            with open(file_path(item["id"]), "rb") as fp:
                while True:
                    chunk = fp.read(1024 * 1024)
                    if not chunk:
                        break
                    sha.update(chunk)
                    md5.update(chunk)
        except OSError:
            continue
        with LOCK:
            item["sha256"] = sha.hexdigest()
            item["md5"] = md5.hexdigest()
            save_state()
        done += 1
    if done:
        print(f"  已补算 {done} 个文件的校验值")


# ---------------------------------------------------------------- 页面

PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<title>·</title>
<link rel="icon" href="data:,">
<style>
:root{
  --bg:#ffffff; --bg-subtle:#f6f8fa; --bg-inset:#f6f8fa; --border:#d0d7de; --border-muted:#d8dee4;
  --fg:#1f2328; --fg-muted:#656d76; --fg-subtle:#8c959f;
  --accent:#0969da; --accent-subtle:#ddf4ff;
  --btn-bg:#f6f8fa; --btn-hover:#eef1f4; --btn-border:rgba(31,35,40,.15);
  --success:#1f883d; --success-hover:#1a7f37; --danger:#cf222e; --danger-subtle:#ffebe9;
  --shadow:0 1px 0 rgba(31,35,40,.04); --radius:6px;
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans","PingFang SC","Microsoft YaHei",Helvetica,Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0d1117; --bg-subtle:#161b22; --bg-inset:#010409; --border:#30363d; --border-muted:#21262d;
    --fg:#e6edf3; --fg-muted:#8b949e; --fg-subtle:#6e7681;
    --accent:#2f81f7; --accent-subtle:#121d2f;
    --btn-bg:#21262d; --btn-hover:#30363d; --btn-border:rgba(240,246,252,.1);
    --success:#238636; --success-hover:#2ea043; --danger:#f85149; --danger-subtle:#2d1416;
    --shadow:0 1px 0 rgba(1,4,9,.4);
  }
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg); color:var(--fg); font:14px/1.5 var(--font);
  -webkit-font-smoothing:antialiased; padding-bottom:60px;
}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:860px;margin:0 auto;padding:0 16px}

/* 顶栏 */
header{
  position:sticky;top:0;z-index:20;background:var(--bg-subtle);
  border-bottom:1px solid var(--border); backdrop-filter:saturate(180%) blur(6px);
}
.bar{display:flex;align-items:center;gap:8px;height:52px}
.tabs{display:flex;gap:2px}
.tab{
  appearance:none;border:0;background:transparent;color:var(--fg-muted);cursor:pointer;
  font:600 13px/1 var(--font);padding:8px 12px;border-radius:var(--radius);
  display:flex;align-items:center;gap:7px;
}
.tab:hover{background:var(--btn-hover);color:var(--fg)}
.tab[aria-selected=true]{background:var(--accent-subtle);color:var(--accent)}
.tab .n{
  font:600 11px/1 var(--font);padding:3px 6px;border-radius:999px;
  background:var(--btn-bg);border:1px solid var(--btn-border);color:var(--fg-muted);
}
.tab[aria-selected=true] .n{background:transparent;border-color:transparent;color:inherit}
.spacer{flex:1}
.dot{width:8px;height:8px;border-radius:50%;background:var(--success);flex:none;transition:background .2s}
.dot.off{background:var(--fg-subtle)}

/* 按钮 */
.btn{
  appearance:none;cursor:pointer;font:500 12px/1 var(--font);color:var(--fg);
  background:var(--btn-bg);border:1px solid var(--btn-border);border-radius:var(--radius);
  padding:7px 12px;display:inline-flex;align-items:center;gap:6px;white-space:nowrap;
  transition:background .12s,border-color .12s;
}
.btn:hover{background:var(--btn-hover)}
.btn:active{opacity:.85}
.btn:disabled{opacity:.5;cursor:default}
.btn.primary{background:var(--success);border-color:var(--btn-border);color:#fff}
.btn.primary:hover{background:var(--success-hover)}
.btn.ghost{background:transparent;border-color:transparent;color:var(--fg-muted)}
.btn.ghost:hover{background:var(--btn-hover);color:var(--fg)}
.btn.danger:hover{background:var(--danger-subtle);border-color:var(--danger);color:var(--danger)}
.btn svg{width:14px;height:14px;flex:none}

/* 卡片 */
.card{
  border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);
  box-shadow:var(--shadow);margin-top:16px;overflow:hidden;
}
.card-head{
  display:flex;align-items:center;gap:8px;padding:10px 14px;background:var(--bg-subtle);
  border-bottom:1px solid var(--border);font-weight:600;font-size:13px;
}
.card-head .muted{font-weight:400;color:var(--fg-muted)}
.card-body{padding:14px}

textarea{
  width:100%;min-height:96px;resize:vertical;padding:10px 12px;font:13px/1.6 var(--mono);
  color:var(--fg);background:var(--bg-inset);border:1px solid var(--border);
  border-radius:var(--radius);outline:none;
}
textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-subtle);background:var(--bg)}
textarea::placeholder{color:var(--fg-subtle)}
.row{display:flex;gap:8px;align-items:center;margin-top:10px}
.hint{color:var(--fg-muted);font-size:12px}
@media (max-width:560px){ .ops .vfy{display:none} }   /* 手机上前面的校验值已可点开，省地方 */
kbd{
  font:11px/1.4 var(--mono);padding:2px 5px;border:1px solid var(--border);
  border-bottom-width:2px;border-radius:5px;background:var(--bg-subtle);color:var(--fg-muted);
}

/* 列表 */
.list{border-top:1px solid var(--border)}
.item{display:flex;gap:12px;padding:12px 14px;border-bottom:1px solid var(--border-muted);align-items:flex-start}
.item:last-child{border-bottom:0}
.item:hover{background:var(--bg-subtle)}
.item .grow{flex:1;min-width:0}
.text{
  font:12.5px/1.6 var(--mono);white-space:pre-wrap;word-break:break-word;
  max-height:220px;overflow:auto;margin:0;
}
.meta{display:flex;gap:10px;align-items:center;color:var(--fg-muted);font-size:12px;margin-top:6px;flex-wrap:wrap}
.acts{display:flex;gap:4px;flex:none}
.ops{display:flex;gap:4px;opacity:0;transition:opacity .12s}
.item:hover .ops,.item:focus-within .ops{opacity:1}
@media (hover:none){.ops{opacity:1}}
.fname{
  font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;
  color:var(--fg);
}
.fname:hover{color:var(--accent)}
.ficon{
  width:32px;height:32px;flex:none;border-radius:var(--radius);background:var(--bg-subtle);
  border:1px solid var(--border);display:grid;place-items:center;color:var(--fg-muted);
}
.ficon svg{width:16px;height:16px}
.thumb{
  width:32px;height:32px;flex:none;border-radius:var(--radius);object-fit:cover;
  border:1px solid var(--border);background:var(--bg-subtle);
}

/* 上传区 */
.drop{
  border:1px dashed var(--border);border-radius:var(--radius);background:var(--bg-subtle);
  padding:26px 16px;text-align:center;color:var(--fg-muted);cursor:pointer;
  transition:border-color .15s,background .15s;
}
.drop:hover{border-color:var(--fg-subtle)}
.drop.over{border-color:var(--accent);background:var(--accent-subtle);color:var(--accent)}
.drop b{color:var(--fg);font-weight:600}
.drop .ic{color:var(--fg-subtle);margin-bottom:6px}
.drop .ic svg{width:22px;height:22px}

/* 空状态 */
.empty{padding:30px 16px;text-align:center;color:var(--fg-subtle);font-size:13px}

/* 进度 / 提示 */
#prog{position:fixed;left:0;right:0;top:0;height:2px;z-index:60;background:transparent}
#prog > i{display:block;height:100%;width:0;background:var(--accent);transition:width .15s}
#toasts{position:fixed;left:50%;transform:translateX(-50%);bottom:20px;z-index:70;display:flex;flex-direction:column;gap:8px;align-items:center}
.toast{
  background:var(--bg-subtle);border:1px solid var(--border);border-radius:var(--radius);
  padding:8px 14px;font-size:12.5px;box-shadow:0 4px 16px rgba(0,0,0,.14);max-width:80vw;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}
.toast.err{border-color:var(--danger);color:var(--danger)}

#veil{
  position:fixed;inset:0;z-index:50;display:none;place-items:center;
  background:color-mix(in srgb,var(--bg) 80%,transparent);backdrop-filter:blur(2px);
}
#veil.on{display:grid}
#veil .box{
  border:2px dashed var(--accent);border-radius:12px;padding:34px 46px;color:var(--accent);
  font-weight:600;background:var(--accent-subtle);
}

/* 校验值卡片 */
.hashlink{
  font-family:var(--mono);font-size:11.5px;color:var(--fg-muted);cursor:pointer;
  border-bottom:1px dashed var(--border);padding-bottom:1px;white-space:nowrap;
}
.hashlink:hover{color:var(--accent);border-color:var(--accent)}
#modal{
  position:fixed;inset:0;z-index:80;display:none;place-items:center;padding:16px;
  background:rgba(31,35,40,.45);backdrop-filter:blur(2px);
}
#modal.on{display:grid}
.sheet{
  background:var(--bg);border:1px solid var(--border);border-radius:10px;width:100%;max-width:600px;
  box-shadow:0 12px 32px rgba(0,0,0,.26);overflow:hidden;
}
.sheet-head{
  display:flex;align-items:center;justify-content:space-between;gap:10px;
  padding:10px 14px;background:var(--bg-subtle);border-bottom:1px solid var(--border);
  font-size:13px;font-weight:600;
}
.sheet-body{padding:14px;display:flex;flex-direction:column;gap:12px}
.sheet .fname{white-space:normal;word-break:break-all;font-size:14px}
.kv{display:grid;grid-template-columns:58px 1fr auto;gap:8px;align-items:center}
.kv > span{color:var(--fg-muted);font-size:12px}
.kv code{
  font:12px/1.6 var(--mono);word-break:break-all;background:var(--bg-inset);
  border:1px solid var(--border);border-radius:var(--radius);padding:5px 8px;
}
.sheet .tip{color:var(--fg-muted);font-size:12px;line-height:1.7;margin:0}
.sheet .tip code{font:11.5px var(--mono);background:var(--bg-inset);border:1px solid var(--border);border-radius:4px;padding:1px 4px}
.hidden{display:none!important}
</style>
</head>
<body>
<div id="prog"><i></i></div>

<header>
  <div class="wrap bar">
    <div class="tabs" role="tablist">
      <button class="tab" id="tab-text" role="tab" aria-selected="true">
        文本 <span class="n" id="cnt-text">0</span>
      </button>
      <button class="tab" id="tab-file" role="tab" aria-selected="false">
        文件 <span class="n" id="cnt-file">0</span>
      </button>
    </div>
    <div class="spacer"></div>
    <button class="btn ghost danger" id="clear">清空</button>
    <span class="dot" id="dot" title="已连接"></span>
  </div>
</header>

<main class="wrap">
  <!-- 文本 -->
  <section id="pane-text">
    <div class="card">
      <div class="card-body">
        <textarea id="ta" placeholder="粘贴或输入文本，Ctrl/⌘ + Enter 发送"></textarea>
        <div class="row">
          <button class="btn primary" id="send">发送</button>
          <span class="hint">
            在页面任意位置 <kbd>Ctrl</kbd>+<kbd>V</kbd> 粘贴文本或图片
          </span>
        </div>
      </div>
      <div class="list" id="snippets"></div>
    </div>
  </section>

  <!-- 文件 -->
  <section id="pane-file" class="hidden">
    <div class="card">
      <div class="card-body">
        <div class="drop" id="drop">
          <div class="ic">
            <svg viewBox="0 0 16 16" fill="currentColor"><path d="M2.5 1A1.5 1.5 0 0 0 1 2.5v11A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-11A1.5 1.5 0 0 0 13.5 1h-11ZM0 2.5A2.5 2.5 0 0 1 2.5 0h11A2.5 2.5 0 0 1 16 2.5v11a2.5 2.5 0 0 1-2.5 2.5h-11A2.5 2.5 0 0 1 0 13.5v-11ZM8 3.5 11.5 7H9v4H7V7H4.5L8 3.5Z"/></svg>
          </div>
          拖拽文件到这里，或 <b>点击选择</b>
          <div class="hint" style="margin-top:6px">可以整个页面拖入，支持多选、大文件</div>
        </div>
        <input type="file" id="pick" multiple class="hidden">
      </div>
      <div class="list" id="files"></div>
    </div>
  </section>
</main>

<div id="veil"><div class="box">松开即可上传</div></div>

<div id="modal">
  <div class="sheet">
    <div class="sheet-head">
      <span>校验值</span>
      <button class="btn ghost" id="m-close">关闭</button>
    </div>
    <div class="sheet-body">
      <div class="fname" id="m-name"></div>
      <div class="kv"><span>大小</span><code id="m-size"></code></div>
      <div class="kv"><span>SHA-256</span><code id="m-sha"></code><button class="btn ghost" id="m-cp-sha">复制</button></div>
      <div class="kv"><span>MD5</span><code id="m-md5"></code><button class="btn ghost" id="m-cp-md5">复制</button></div>
      <p class="tip">
        下载完成后在接收端核对，一致就说明文件完好：<br>
        macOS / Linux <code>shasum -a 256 文件名</code>　Windows <code>certutil -hashfile 文件名 SHA256</code><br>
        大文件下载支持断点续传，中断后用 <code>curl -C - -O 链接</code> 或下载工具接着下。
      </p>
    </div>
  </div>
</div>
<div id="toasts"></div>

<script>
const $ = s => document.querySelector(s);
const el = (tag, cls) => { const n = document.createElement(tag); if (cls) n.className = cls; return n; };
const KB = 1024, MB = KB*1024, GB = MB*1024;

function fmtSize(b){
  if (b < KB) return b + ' B';
  if (b < MB) return (b/KB).toFixed(1) + ' KB';
  if (b < GB) return (b/MB).toFixed(1) + ' MB';
  return (b/GB).toFixed(2) + ' GB';
}
function fmtTime(ts){
  const d = Date.now()/1000 - ts;
  if (d < 60) return '刚刚';
  if (d < 3600) return Math.floor(d/60) + ' 分钟前';
  if (d < 86400) return Math.floor(d/3600) + ' 小时前';
  const t = new Date(ts*1000);
  const p = n => String(n).padStart(2,'0');
  return `${t.getMonth()+1}月${t.getDate()}日 ${p(t.getHours())}:${p(t.getMinutes())}`;
}
function toast(msg, err){
  const n = el('div', 'toast' + (err ? ' err' : ''));
  n.textContent = msg;
  $('#toasts').appendChild(n);
  setTimeout(() => n.remove(), 2400);
}
const ICON = {
  copy:'<path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 0 1 0 1.5h-1.5a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-1.5a.75.75 0 0 1 1.5 0v1.5A1.75 1.75 0 0 1 9.25 16h-7.5A1.75 1.75 0 0 1 0 14.25Z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25Z"/>',
  down:'<path d="M2.75 14A1.75 1.75 0 0 1 1 12.25v-2.5a.75.75 0 0 1 1.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 0 0 .25-.25v-2.5a.75.75 0 0 1 1.5 0v2.5A1.75 1.75 0 0 1 13.25 14Z"/><path d="M7.25 7.689V2a.75.75 0 0 1 1.5 0v5.689l1.97-1.969a.749.749 0 1 1 1.06 1.06l-3.25 3.25a.749.749 0 0 1-1.06 0L4.22 6.78a.749.749 0 1 1 1.06-1.06l1.97 1.969Z"/>',
  trash:'<path d="M11 1.75V3h2.25a.75.75 0 0 1 0 1.5H2.75a.75.75 0 0 1 0-1.5H5V1.75C5 .784 5.784 0 6.75 0h2.5C10.216 0 11 .784 11 1.75ZM4.496 6.675l.66 6.6a.25.25 0 0 0 .249.225h5.19a.25.25 0 0 0 .249-.225l.66-6.6a.75.75 0 0 1 1.492.149l-.66 6.6A1.748 1.748 0 0 1 10.595 15h-5.19a1.75 1.75 0 0 1-1.741-1.575l-.66-6.6a.75.75 0 1 1 1.492-.15Z"/>',
  file:'<path d="M2 1.75C2 .784 2.784 0 3.75 0h6.586c.464 0 .909.184 1.237.513l2.914 2.914c.329.328.513.773.513 1.237v9.586A1.75 1.75 0 0 1 13.25 16h-9.5A1.75 1.75 0 0 1 2 14.25Zm1.75-.25a.25.25 0 0 0-.25.25v12.5c0 .138.112.25.25.25h9.5a.25.25 0 0 0 .25-.25V6h-2.75A1.75 1.75 0 0 1 9 4.25V1.5Zm6.75.062V4.25c0 .138.112.25.25.25h2.688l-.011-.013-2.914-2.914-.013-.011Z"/>',
  shield:'<path d="M8 0c-.69 0-1.843.265-2.928.56-1.11.3-2.229.655-2.887.87a1.54 1.54 0 0 0-1.044 1.262c-.596 4.477.787 7.795 2.465 9.99a11.777 11.777 0 0 0 2.517 2.453c.386.273.744.482 1.048.625.28.132.581.24.829.24s.548-.108.829-.24a7.159 7.159 0 0 0 1.048-.625 11.775 11.775 0 0 0 2.517-2.453c1.678-2.195 3.061-5.513 2.465-9.99a1.541 1.541 0 0 0-1.044-1.263 62.467 62.467 0 0 0-2.887-.87C9.843.265 8.69 0 8 0Zm0 1.5c.56 0 1.598.228 2.653.512 1.06.286 2.121.62 2.744.827.06.02.104.072.113.135.53 3.975-.65 6.797-2.03 8.6a10.28 10.28 0 0 1-2.196 2.142c-.344.243-.646.421-.881.53a2.35 2.35 0 0 1-.403.148 2.35 2.35 0 0 1-.403-.148 10.28 10.28 0 0 1-.881-.53 10.28 10.28 0 0 1-2.195-2.141c-1.38-1.804-2.561-4.626-2.031-8.601a.166.166 0 0 1 .113-.135 62.3 62.3 0 0 1 2.744-.827C6.402 1.728 7.44 1.5 8 1.5Zm-.75 4.75v3.5a.75.75 0 0 1-1.5 0v-3.5a.75.75 0 0 1 1.5 0Zm1.5.75a.75.75 0 0 0 0 1.5h.008a.75.75 0 0 0 0-1.5H8.75Z"/>'
};
function icon(name, cls){
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('viewBox', '0 0 16 16'); s.setAttribute('fill', 'currentColor');
  if (cls) s.setAttribute('class', cls);
  s.innerHTML = ICON[name];
  return s;
}
function button(label, ic, cls){
  const b = el('button', 'btn ' + (cls || ''));
  if (ic) b.appendChild(icon(ic));
  if (label) b.appendChild(document.createTextNode(label));
  return b;
}
async function copyText(text){
  try { await navigator.clipboard.writeText(text); return true; }
  catch (e) {
    const ta = el('textarea'); ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (_) {}
    ta.remove(); return ok;
  }
}

/* ---------------------------------------------------------- 状态与渲染 */
let cache = '', tab = 'text', data = {snippets: [], files: []};

function setStatus(ok){
  const d = $('#dot');
  d.classList.toggle('off', !ok);
  d.title = ok ? '已连接' : '连接中断';
}
function switchTab(name){
  tab = name;
  $('#tab-text').setAttribute('aria-selected', name === 'text');
  $('#tab-file').setAttribute('aria-selected', name === 'file');
  $('#pane-text').classList.toggle('hidden', name !== 'text');
  $('#pane-file').classList.toggle('hidden', name !== 'file');
  try { history.replaceState(null, '', name === 'file' ? '#files' : location.pathname); } catch (_) {}
}
function emptyRow(text){
  const n = el('div', 'empty'); n.textContent = text; return n;
}

function render(d){
  data = d;
  $('#cnt-text').textContent = d.snippets.length;
  $('#cnt-file').textContent = d.files.length;

  const box = $('#snippets');
  box.textContent = '';
  if (!d.snippets.length) box.appendChild(emptyRow('还没有文本'));
  for (const s of d.snippets){
    const it = el('div', 'item');
    const grow = el('div', 'grow');
    const pre = el('pre', 'text'); pre.textContent = s.text;
    const meta = el('div', 'meta');
    meta.appendChild(el('span')).textContent = fmtTime(s.ts);
    meta.appendChild(el('span')).textContent = s.text.length + ' 字符';
    grow.append(pre, meta);

    const ops = el('div', 'ops');
    const cp = button('复制', 'copy', 'ghost');
    cp.onclick = async () => toast(await copyText(s.text) ? '已复制' : '复制失败', false);
    const del = button('', 'trash', 'ghost danger');
    del.title = '删除';
    del.onclick = () => api('DELETE', '/api/snippets/' + s.id);
    ops.append(cp, del);
    it.append(grow, ops);
    box.appendChild(it);
  }

  const fbox = $('#files');
  fbox.textContent = '';
  if (!d.files.length) fbox.appendChild(emptyRow('还没有文件'));
  for (const f of d.files){
    const it = el('div', 'item');
    const isImg = /^image\//.test(f.type || '');
    let lead;
    if (isImg){
      lead = el('img', 'thumb'); lead.src = '/f/' + f.id; lead.alt = '';
    } else {
      lead = el('div', 'ficon'); lead.appendChild(icon('file'));
    }
    const grow = el('div', 'grow');
    const a = el('a', 'fname');
    a.href = '/f/' + f.id; a.download = f.name; a.textContent = f.name; a.title = f.name;
    const meta = el('div', 'meta');
    const t1 = el('span'); t1.textContent = fmtSize(f.size);
    const t2 = el('span'); t2.textContent = fmtTime(f.ts);
    meta.append(t1, t2);
    const hl = el('span', 'hashlink');
    if (f.sha256){
      hl.textContent = 'SHA-256 ' + f.sha256.slice(0, 8) + '…' + f.sha256.slice(-4);
      hl.title = 'SHA-256 ' + f.sha256 + '\nMD5 ' + f.md5 + '\n点击查看/复制';
    } else {
      hl.textContent = '校验值计算中…';
      hl.title = '正在后台计算';
    }
    hl.onclick = () => openVerify(f);
    meta.appendChild(hl);
    grow.append(a, meta);

    const ops = el('div', 'ops');
    const vf = button('校验', 'shield', 'ghost vfy');
    vf.title = '查看 SHA-256 / MD5 校验值';
    vf.onclick = () => openVerify(f);
    const cp = button('', 'copy', 'ghost');
    cp.title = '复制下载链接';
    cp.onclick = async () => {
      const url = location.origin + '/f/' + f.id;
      toast(await copyText(url) ? '已复制下载链接' : '复制失败');
    };
    const dn = button('下载', 'down', 'ghost');
    dn.title = '支持断点续传（浏览器自动续，或用下载工具接续）';
    dn.onclick = () => { location.href = '/f/' + f.id; };
    const del = button('', 'trash', 'ghost danger');
    del.title = '删除';
    del.onclick = () => api('DELETE', '/api/files/' + f.id);
    ops.append(vf, cp, dn, del);
    it.append(lead, grow, ops);
    fbox.appendChild(it);
  }
}

/* 校验值卡片 */
function openVerify(f){
  $('#m-name').textContent = f.name;
  $('#m-size').textContent = fmtSize(f.size) + '（' + f.size + ' 字节）';
  $('#m-sha').textContent = f.sha256 || '（后台计算中，稍后刷新）';
  $('#m-md5').textContent = f.md5 || '（后台计算中，稍后刷新）';
  $('#m-cp-sha').onclick = async () => toast(await copyText(f.sha256 || '') ? '已复制 SHA-256' : '复制失败');
  $('#m-cp-md5').onclick = async () => toast(await copyText(f.md5 || '') ? '已复制 MD5' : '复制失败');
  $('#modal').classList.add('on');
}
function closeVerify(){ $('#modal').classList.remove('on'); }
$('#m-close').onclick = closeVerify;
$('#modal').addEventListener('click', e => { if (e.target === $('#modal')) closeVerify(); });
addEventListener('keydown', e => { if (e.key === 'Escape') closeVerify(); });

async function api(method, url, body){
  const opt = {method, cache: 'no-store'};
  if (body !== undefined){
    opt.headers = {'Content-Type': 'application/json'};
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(url, opt);
  if (!r.ok) toast('操作失败 (' + r.status + ')', true);
  await load(true);
  return r;
}

async function load(force){
  try {
    const r = await fetch('/api/state', {cache: 'no-store'});
    const d = await r.json();
    const key = JSON.stringify(d);
    if (force || key !== cache){ cache = key; render(d); }
    setStatus(true);
  } catch (e){ setStatus(false); }
}

/* ---------------------------------------------------------- 上传 */
let uploading = 0;
function progress(p){
  const bar = $('#prog > i');
  bar.style.width = p === null ? '0' : (p * 100).toFixed(1) + '%';
}
function uploadOne(file){
  return new Promise(resolve => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/files?name=' + encodeURIComponent(file.name));
    xhr.upload.onprogress = e => { if (e.lengthComputable) progress(e.loaded / e.total); };
    xhr.onload = () => {
      if (xhr.status !== 200) toast('上传失败：' + file.name, true);
      else toast('已上传 ' + file.name);
      resolve();
    };
    xhr.onerror = () => { toast('上传中断：' + file.name, true); resolve(); };
    xhr.send(file);
  });
}
async function upload(files){
  const list = Array.from(files || []);
  if (!list.length) return;
  uploading++;
  progress(0);
  switchTab('file');
  for (const f of list) await uploadOne(f);
  uploading--;
  progress(null);
  await load(true);
}

/* ---------------------------------------------------------- 事件 */
$('#send').onclick = async () => {
  const ta = $('#ta');
  const text = ta.value;
  if (!text.trim()){ toast('内容为空', true); return; }
  const r = await api('POST', '/api/snippets', {text});
  if (r.ok) ta.value = '';
};
$('#ta').addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter'){ e.preventDefault(); $('#send').click(); }
});
$('#clear').onclick = () => {
  if (confirm('清空全部文本和文件？')) api('DELETE', '/api/all');
};
$('#tab-text').onclick = () => switchTab('text');
$('#tab-file').onclick = () => switchTab('file');

const pick = $('#pick');
$('#drop').onclick = () => pick.click();
pick.onchange = () => { upload(pick.files); pick.value = ''; };

let dragDepth = 0, lastDrag = 0;
const veil = $('#veil');
function hasFiles(e){
  return e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
}
function hideVeil(){ dragDepth = 0; veil.classList.remove('on'); }
addEventListener('dragenter', e => {
  if (!hasFiles(e)) return;
  e.preventDefault(); dragDepth++; lastDrag = Date.now(); veil.classList.add('on');
});
addEventListener('dragover', e => {
  if (!hasFiles(e)) return;
  e.preventDefault(); lastDrag = Date.now(); veil.classList.add('on');
});
addEventListener('dragleave', e => {
  if (!hasFiles(e)) return;
  dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) veil.classList.remove('on');
});
addEventListener('dragend', hideVeil);
addEventListener('drop', e => {
  if (!hasFiles(e)) return;
  e.preventDefault(); hideVeil();
  upload(e.dataTransfer.files);
});
// 兜底：鼠标已经离开窗口但仍收到过 dragenter 时，收起遮罩
setInterval(() => { if (veil.classList.contains('on') && Date.now() - lastDrag > 800) hideVeil(); }, 400);

// 全局粘贴：文本进输入框，图片/文件直接上传
addEventListener('paste', e => {
  if (e.target === $('#ta')) return;      // 输入框里交给浏览器默认行为
  const cd = e.clipboardData;
  if (!cd) return;
  const files = Array.from(cd.files || []);
  const imgs = files.filter(f => /^image\//.test(f.type));
  if (imgs.length){
    e.preventDefault();
    const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
    const named = imgs.map((f, i) => new File([f], f.name || ('粘贴图片-' + stamp + (i ? '-' + i : '') + '.png'), {type: f.type}));
    upload(named);
    return;
  }
  const text = cd.getData('text/plain') || '';
  if (text && !e.target.closest('textarea, input')){
    e.preventDefault();
    switchTab('text');
    const ta = $('#ta');
    ta.value = ta.value ? ta.value.replace(/\n?$/, '\n') + text : text;
    ta.focus();
    toast('已粘贴到输入框，回车发送');
  }
});

load(true);
if (location.hash === '#files') switchTab('file');
setInterval(() => { if (!uploading) load(false); }, 2000);
</script>
</body>
</html>
"""


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "share"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # -- 工具 ------------------------------------------------------------
    def send_bytes(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, obj, code: int = 200) -> None:
        self.send_bytes(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                        "application/json; charset=utf-8")

    def send_text(self, code: int, msg: str) -> None:
        self.send_bytes(code, msg.encode("utf-8"), "text/plain; charset=utf-8")

    def read_body(self, limit: int) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > limit:
            return None
        return self.rfile.read(length)

    def log_message(self, fmt, *args):  # 轮询太吵，不记录
        if "/api/state" in (self.requestline or ""):
            return
        print(f"  {self.address_string()}  {self.requestline}  -> {args[1] if len(args) > 1 else ''}")

    # -- GET -------------------------------------------------------------
    def do_GET(self):
        url = urlparse(self.path)
        path = unquote(url.path)

        if path in ("/", "/index.html"):
            return self.send_bytes(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        if path == "/favicon.ico":
            return self.send_bytes(204, b"", "image/x-icon")
        if path == "/api/state":
            with LOCK:
                return self.send_json({
                    "now": time.time(),
                    "snippets": STATE["snippets"],
                    "files": [{k: f.get(k, "") for k in
                               ("id", "name", "size", "type", "ts", "sha256", "md5")}
                              for f in STATE["files"]],
                })
        if path.startswith("/f/"):
            return self.download(path[3:])
        self.send_text(404, "404")

    # HEAD 和 GET 走同一套逻辑：下载管理工具靠它探测大小和是否支持断点续传
    def do_HEAD(self):
        self.do_GET()

    # -- POST ------------------------------------------------------------
    def do_POST(self):
        url = urlparse(self.path)
        path = unquote(url.path)

        if path == "/api/snippets":
            body = self.read_body(MAX_SNIPPET + 1024)
            if body is None:
                return self.send_text(400, "bad body")
            try:
                text = json.loads(body.decode("utf-8")).get("text", "")
            except (ValueError, AttributeError):
                return self.send_text(400, "bad json")
            if not isinstance(text, str) or not text.strip():
                return self.send_text(400, "empty")
            item = {"id": uuid.uuid4().hex[:12], "text": text[:MAX_SNIPPET], "ts": time.time()}
            with LOCK:
                STATE["snippets"].insert(0, item)
                del STATE["snippets"][300:]          # 最多保留 300 条
                save_state()
            return self.send_json(item)

        if path == "/api/files":
            return self.upload(parse_qs(url.query))

        self.send_text(404, "404")

    # -- DELETE ----------------------------------------------------------
    def do_DELETE(self):
        path = unquote(urlparse(self.path).path)
        if path == "/api/all":
            with LOCK:
                for f in STATE["files"]:
                    try:
                        os.remove(file_path(f["id"]))
                    except OSError:
                        pass
                STATE["snippets"].clear()
                STATE["files"].clear()
                save_state()
            return self.send_json({"ok": True})

        m = path.rsplit("/", 1)
        if len(m) == 2 and m[0] == "/api/snippets":
            with LOCK:
                STATE["snippets"][:] = [s for s in STATE["snippets"] if s["id"] != m[1]]
                save_state()
            return self.send_json({"ok": True})

        if len(m) == 2 and m[0] == "/api/files":
            with LOCK:
                keep = []
                for f in STATE["files"]:
                    if f["id"] == m[1]:
                        try:
                            os.remove(file_path(f["id"]))
                        except OSError:
                            pass
                    else:
                        keep.append(f)
                STATE["files"] = keep
                save_state()
            return self.send_json({"ok": True})

        self.send_text(404, "404")

    # -- 业务 ------------------------------------------------------------
    def upload(self, query):
        declared = self.headers.get("Content-Length")
        if declared is None:                       # 没有长度就没法判断要收多少
            return self.send_text(400, "missing content-length")
        try:
            length = int(declared)
        except ValueError:
            return self.send_text(400, "bad content-length")
        if length < 0:
            return self.send_text(400, "bad content-length")
        # 注意：length == 0 是合法上传（空文件），不能拒
        if length > MAX_UPLOAD:
            return self.send_text(413, "too large")

        raw = unquote(query.get("name", ["unnamed"])[0])
        name = os.path.basename(raw.replace("\\", "/")).strip() or "unnamed"

        fid = uuid.uuid4().hex[:16]
        dest = file_path(fid)
        left = length
        sha, md5 = hashers()
        try:
            with open(dest, "wb") as fp:
                while left > 0:
                    chunk = self.rfile.read(min(262144, left))
                    if not chunk:
                        break
                    fp.write(chunk)
                    sha.update(chunk)
                    md5.update(chunk)
                    left -= len(chunk)
        except OSError:
            try:
                os.remove(dest)
            except OSError:
                pass
            return self.send_text(500, "write failed")

        if left > 0:                               # 客户端中断
            try:
                os.remove(dest)
            except OSError:
                pass
            return self.send_text(400, "incomplete")

        ctype = (mimetypes.guess_type(name)[0]
                 or self.headers.get("Content-Type")
                 or "application/octet-stream")
        item = {"id": fid, "name": name, "size": length, "type": ctype, "ts": time.time(),
                "sha256": sha.hexdigest(), "md5": md5.hexdigest()}
        with LOCK:
            STATE["files"].insert(0, item)
            save_state()
        self.send_json(item)

    @staticmethod
    def parse_range(header: str, size: int):
        """解析单段 Range。返回 (start, end)；"unsat" 表示越界；None 表示应忽略（回整文件）。"""
        if not header or not header.lower().startswith("bytes="):
            return None
        spec = header[6:].strip()
        if "," in spec:                       # 多段不支持，按 RFC 回退成 200 整文件
            return None
        first, _, last = spec.partition("-")
        first, last = first.strip(), last.strip()
        try:
            if not first:                     # bytes=-N → 末尾 N 字节
                n = int(last)
                if n <= 0:
                    return "unsat"
                return (max(0, size - n), size - 1)
            start = int(first)
            if start >= size:
                return "unsat"
            end = int(last) if last else size - 1
            if end < start:
                return None
            return (start, min(end, size - 1))
        except ValueError:
            return None

    def download(self, fid):
        with LOCK:
            item = next((f for f in STATE["files"] if f["id"] == fid), None)
        if not item:
            return self.send_text(404, "404")

        path = file_path(fid)
        try:
            st = os.stat(path)
        except OSError:
            return self.send_text(404, "404")
        size = st.st_size
        etag = f'"{size:x}-{int(st.st_mtime):x}"'
        last_mod = self.date_time_string(int(st.st_mtime))

        # 条件请求：内容没变 → 304，浏览器/下载器可以直接用本地缓存
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Last-Modified", last_mod)
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        start, end, code = 0, max(size - 1, 0), 200
        header = self.headers.get("Range")
        if header and size > 0:
            # If-Range 不匹配说明文件已经换过了，只能回整文件
            cond = self.headers.get("If-Range")
            fresh = cond is None or cond.strip() in (etag, last_mod)
            rng = self.parse_range(header, size)
            if rng == "unsat":
                if fresh:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.send_header("Content-Length", "0")
                    self.send_header("Accept-Ranges", "bytes")
                    self.end_headers()
                    return
            elif rng and fresh:
                start, end, code = rng[0], rng[1], 206

        length = end - start + 1 if size else 0
        stem, ext = os.path.splitext(item["name"])
        ascii_name = stem.encode("ascii", "ignore").decode()
        ascii_name = "".join(c for c in ascii_name if c.isalnum() or c in " ._-").strip(" ._-")
        if len(ascii_name) < 2:                        # 纯中文名 → 通用 ASCII 回退名
            ascii_name = "download"
        ascii_name += ext[:16]
        disp = f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(item["name"])}'

        self.send_response(code)
        self.send_header("Content-Type", item.get("type") or "application/octet-stream")
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Disposition", disp)
        self.send_header("Last-Modified", last_mod)
        self.send_header("ETag", etag)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Cache-Control", "no-store")
        if code == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.end_headers()

        if self.command == "HEAD" or not length:
            return

        try:
            with open(path, "rb") as fp:
                fp.seek(start)
                left = length
                while left > 0:
                    chunk = fp.read(min(262144, left))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    left -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True      # 客户端中途断开：关连接，避免 keep-alive 串包


# ---------------------------------------------------------------- 启动

def lan_ips() -> list[str]:
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    try:  # 拿“默认出口”的那张网卡
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127."))


def main() -> None:
    load_state()
    threading.Thread(target=fill_missing_hashes, daemon=True).start()

    def bye(*_):
        raise KeyboardInterrupt

    for sig in ("SIGINT", "SIGTERM"):
        try:
            signal.signal(getattr(signal, sig), bye)
        except (ValueError, OSError, AttributeError):
            pass

    for _ in range(20):
        try:
            httpd = ThreadingHTTPServer((HOST, PORT), Handler)
            break
        except OSError:
            print(f"端口 {PORT} 被占用，试 {PORT + 1} …")
            globals()["PORT"] = PORT + 1
    else:
        raise SystemExit("找不到可用端口，用 PORT=xxxx python3 share.py 指定一个")

    httpd.daemon_threads = True
    ips = lan_ips()

    print("\n  局域网中转站已启动（手机和电脑连同一个 Wi-Fi）\n")
    for ip in ips or ["127.0.0.1"]:
        print(f"    http://{ip}:{PORT}")
    print(f"\n    http://127.0.0.1:{PORT}   ← 本机")
    print(f"\n  数据目录：{DATA_DIR}")
    print("  Ctrl+C 退出\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        print("\n  已停止\n")


if __name__ == "__main__":
    main()
