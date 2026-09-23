"use strict";

const $ = (selector) => document.querySelector(selector);
const loginView = $("#login");
const workspace = $("#workspace");
const loginForm = $("#login-form");
const loginMessage = $("#login-message");
const fileInput = $("#file-input");
const dropZone = $("#drop-zone");
const queueSection = $("#queue-section");
const queueNode = $("#queue");
const filesNode = $("#files");
const emptyNode = $("#empty");
const summaryNode = $("#summary");
const toastNode = $("#toast");

let config = { large_threshold: 128 * 1024 * 1024, chunk_size: 8 * 1024 * 1024 };
let tasks = [];
let pumping = false;
let toastTimer = 0;

const K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);

class Sha256 {
  constructor() {
    this.h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    this.buffer = new Uint8Array(64);
    this.bufferLength = 0;
    this.bytes = 0;
    this.finished = false;
  }

  update(input) {
    if (this.finished) throw new Error("hash already finished");
    const data = input instanceof Uint8Array ? input : new Uint8Array(input);
    this.bytes += data.length;
    let offset = 0;
    while (offset < data.length) {
      const take = Math.min(64 - this.bufferLength, data.length - offset);
      this.buffer.set(data.subarray(offset, offset + take), this.bufferLength);
      this.bufferLength += take;
      offset += take;
      if (this.bufferLength === 64) {
        this.process(this.buffer);
        this.bufferLength = 0;
      }
    }
    return this;
  }

  process(block) {
    const w = new Uint32Array(64);
    for (let i = 0; i < 16; i++) {
      const j = i * 4;
      w[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15], b = w[i - 2];
      const s0 = (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) >>> 0;
      const s1 = (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = this.h;
    for (let i = 0; i < 64; i++) {
      const s1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (h + s1 + ch + K[i] + w[i]) >>> 0;
      const s0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (s0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    this.h[0] = (this.h[0] + a) >>> 0; this.h[1] = (this.h[1] + b) >>> 0;
    this.h[2] = (this.h[2] + c) >>> 0; this.h[3] = (this.h[3] + d) >>> 0;
    this.h[4] = (this.h[4] + e) >>> 0; this.h[5] = (this.h[5] + f) >>> 0;
    this.h[6] = (this.h[6] + g) >>> 0; this.h[7] = (this.h[7] + h) >>> 0;
  }

  digest() {
    if (!this.finished) {
      const bitHi = Math.floor(this.bytes / 0x20000000);
      const bitLo = (this.bytes << 3) >>> 0;
      this.buffer[this.bufferLength++] = 0x80;
      if (this.bufferLength > 56) {
        this.buffer.fill(0, this.bufferLength);
        this.process(this.buffer);
        this.bufferLength = 0;
      }
      this.buffer.fill(0, this.bufferLength, 56);
      this.buffer[56] = bitHi >>> 24; this.buffer[57] = bitHi >>> 16;
      this.buffer[58] = bitHi >>> 8; this.buffer[59] = bitHi;
      this.buffer[60] = bitLo >>> 24; this.buffer[61] = bitLo >>> 16;
      this.buffer[62] = bitLo >>> 8; this.buffer[63] = bitLo;
      this.process(this.buffer);
      this.finished = true;
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      out[i * 4] = this.h[i] >>> 24; out[i * 4 + 1] = this.h[i] >>> 16;
      out[i * 4 + 2] = this.h[i] >>> 8; out[i * 4 + 3] = this.h[i];
    }
    return out;
  }

  hex() { return bytesToHex(this.digest()); }
}

function rotr(value, bits) { return (value >>> bits) | (value << (32 - bits)); }
function bytesToHex(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join(""); }
function hexToBytes(hex) { const out = new Uint8Array(hex.length / 2); for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16); return out; }

async function hashBlob(blob, onProgress) {
  const hash = new Sha256();
  const step = 4 * 1024 * 1024;
  for (let offset = 0; offset < blob.size; offset += step) {
    hash.update(new Uint8Array(await blob.slice(offset, Math.min(blob.size, offset + step)).arrayBuffer()));
    if (onProgress) onProgress(Math.min(1, (offset + step) / Math.max(1, blob.size)));
    await yieldFrame();
  }
  return hash.hex();
}

function yieldFrame() { return new Promise(resolve => setTimeout(resolve, 0)); }

async function api(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  let body = {};
  try { body = await response.json(); } catch (_) {}
  if (!response.ok) {
    if (response.status === 401) showLogin();
    throw new Error(body.error || `请求失败 (${response.status})`);
  }
  return body;
}

function showToast(message) {
  clearTimeout(toastTimer);
  toastNode.textContent = message;
  toastNode.classList.add("show");
  toastTimer = setTimeout(() => toastNode.classList.remove("show"), 2600);
}

function showLogin() {
  workspace.hidden = true;
  loginView.hidden = false;
  $("#password").value = "";
  setTimeout(() => $("#username").focus(), 0);
}

async function showWorkspace(session) {
  config = session;
  $("#current-user").textContent = session.username;
  $("#upload-note").textContent = `${formatSize(session.large_threshold)} 起自动分块、校验并可续传`;
  loginView.hidden = true;
  workspace.hidden = false;
  await refreshFiles();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = loginForm.querySelector("button");
  button.disabled = true;
  loginMessage.classList.remove("error");
  loginMessage.textContent = "checking...";
  try {
    const result = await api("/api/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: $("#username").value, password: $("#password").value })
    });
    const session = await api("/api/session");
    await showWorkspace(session);
    if (result.created) showToast("账户已创建");
  } catch (error) {
    loginMessage.classList.add("error");
    loginMessage.textContent = error.message;
    $("#password").select();
  } finally { button.disabled = false; }
});

$("#logout").addEventListener("click", async () => {
  tasks.forEach(task => task.abort?.abort());
  tasks = [];
  renderQueue();
  await api("/api/logout", { method: "POST", body: "{}", headers: { "Content-Type": "application/json" } });
  showLogin();
});

$("#choose-files").addEventListener("click", event => { event.stopPropagation(); fileInput.click(); });
dropZone.addEventListener("click", event => { if (event.target === dropZone || event.target.tagName === "P" || event.target.tagName === "SMALL") fileInput.click(); });
dropZone.addEventListener("keydown", event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); fileInput.click(); } });
fileInput.addEventListener("change", () => { addFiles(fileInput.files); fileInput.value = ""; });

for (const name of ["dragenter", "dragover"]) {
  dropZone.addEventListener(name, event => { event.preventDefault(); if (event.dataTransfer.types.includes("Files")) dropZone.classList.add("dragging"); });
}
for (const name of ["dragleave", "drop"]) {
  dropZone.addEventListener(name, event => { event.preventDefault(); dropZone.classList.remove("dragging"); });
}
dropZone.addEventListener("drop", event => addFiles(event.dataTransfer.files));
window.addEventListener("dragover", event => event.preventDefault());
window.addEventListener("drop", event => event.preventDefault());

function addFiles(list) {
  const added = Array.from(list || []).filter(file => file.size >= 0).map(file => ({
    key: Math.random().toString(36).slice(2), file, state: "queued", progress: 0,
    detail: file.size >= config.large_threshold ? "等待分块上传" : "等待上传",
    uploadId: null, abort: null, cancelled: false
  }));
  tasks.push(...added);
  renderQueue();
  pump();
}

async function pump() {
  if (pumping) return;
  const task = tasks.find(item => item.state === "queued");
  if (!task) return;
  pumping = true;
  task.state = "uploading";
  renderQueue();
  try {
    if (task.file.size >= config.large_threshold) await uploadLarge(task);
    else await uploadSmall(task);
    if (!task.cancelled && task.state === "uploading") {
      task.state = "done";
      task.progress = 1;
      task.detail = "完成 · 校验通过";
      await refreshFiles();
      setTimeout(() => { tasks = tasks.filter(item => item !== task); renderQueue(); }, 2200);
    }
  } catch (error) {
    if (!task.cancelled && task.state !== "paused") {
      task.state = "error";
      task.detail = error.name === "AbortError" ? "已暂停" : error.message;
    }
  } finally {
    task.abort = null;
    pumping = false;
    renderQueue();
    pump();
  }
}

async function uploadSmall(task) {
  task.detail = "校验中";
  const checksum = await hashBlob(task.file, p => { task.progress = p * .12; renderQueue(); });
  if (task.cancelled || task.state === "paused") return;
  task.detail = "上传中";
  await new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    task.abort = { abort: () => xhr.abort() };
    xhr.open("POST", "/api/files/small");
    xhr.setRequestHeader("X-File-Name", encodeURIComponent(task.file.name));
    xhr.setRequestHeader("X-File-Sha256", checksum);
    xhr.upload.onprogress = event => {
      if (event.lengthComputable) task.progress = .12 + event.loaded / event.total * .88;
      renderQueue();
    };
    xhr.onload = () => {
      let body = {}; try { body = JSON.parse(xhr.responseText); } catch (_) {}
      if (xhr.status >= 200 && xhr.status < 300) resolve(body);
      else reject(new Error(body.error || `上传失败 (${xhr.status})`));
    };
    xhr.onerror = () => reject(new Error("网络连接中断"));
    xhr.onabort = () => reject(new DOMException("已暂停", "AbortError"));
    xhr.send(task.file);
  });
}

async function fileKey(file) {
  const hash = new Sha256();
  hash.update(new TextEncoder().encode(`${file.name}\0${file.size}\0${file.lastModified}\0`));
  const sample = 64 * 1024;
  hash.update(new Uint8Array(await file.slice(0, Math.min(file.size, sample)).arrayBuffer()));
  if (file.size > sample) hash.update(new Uint8Array(await file.slice(Math.max(0, file.size - sample)).arrayBuffer()));
  return hash.hex();
}

async function uploadLarge(task) {
  task.detail = "读取续传进度";
  const key = await fileKey(task.file);
  const upload = await api("/api/uploads/init", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: task.file.name, size: task.file.size, file_key: key })
  });
  task.uploadId = upload.id;
  const hashes = new Array(upload.total_chunks);
  let completedBytes = 0;
  for (const chunk of upload.received) {
    hashes[chunk.index] = chunk.checksum;
    completedBytes += chunk.size;
  }
  task.progress = completedBytes / task.file.size;
  task.detail = completedBytes ? `续传 · ${formatSize(completedBytes)} / ${formatSize(task.file.size)}` : "分块上传中";
  renderQueue();

  for (let index = 0; index < upload.total_chunks; index++) {
    if (task.cancelled || task.state === "paused") return;
    if (hashes[index]) continue;
    const start = index * upload.chunk_size;
    const blob = task.file.slice(start, Math.min(task.file.size, start + upload.chunk_size));
    task.detail = `校验分块 ${index + 1} / ${upload.total_chunks}`;
    renderQueue();
    const checksum = await hashBlob(blob);
    let response;
    for (let attempt = 0; attempt < 3; attempt++) {
      task.abort = new AbortController();
      try {
        task.detail = `上传分块 ${index + 1} / ${upload.total_chunks}`;
        renderQueue();
        response = await api(`/api/uploads/${upload.id}/chunks/${index}`, {
          method: "PUT", body: blob, signal: task.abort.signal,
          headers: { "X-Chunk-Sha256": checksum }
        });
        break;
      } catch (error) {
        if (task.cancelled || task.state === "paused" || error.name === "AbortError") throw error;
        if (attempt === 2) throw error;
        task.detail = `重试分块 ${index + 1} / ${upload.total_chunks}`;
        renderQueue();
        await new Promise(resolve => setTimeout(resolve, 600 * (attempt + 1)));
      }
    }
    hashes[index] = response.checksum;
    completedBytes += blob.size;
    task.progress = completedBytes / task.file.size;
    renderQueue();
  }
  if (task.cancelled || task.state === "paused") return;
  const manifest = new Sha256();
  hashes.forEach(hash => manifest.update(hexToBytes(hash)));
  task.detail = "整体校验中";
  renderQueue();
  await api(`/api/uploads/${upload.id}/complete`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ manifest_checksum: manifest.hex() })
  });
  task.uploadId = null;
}

function renderQueue() {
  queueSection.hidden = tasks.length === 0;
  queueNode.replaceChildren(...tasks.map(task => {
    const item = document.createElement("div");
    item.className = "queue-item";
    const name = document.createElement("div"); name.className = "queue-name"; name.textContent = task.file.name;
    const meta = document.createElement("div"); meta.className = "queue-meta"; meta.textContent = `${task.detail} · ${formatSize(task.file.size)}`;
    const actions = document.createElement("div"); actions.className = "queue-actions";
    if (!['done'].includes(task.state)) {
      const toggle = document.createElement("button"); toggle.className = "text-button"; toggle.type = "button";
      toggle.textContent = task.state === "paused" || task.state === "error" ? "继续" : task.state === "queued" ? "等待" : "暂停";
      toggle.disabled = task.state === "queued";
      toggle.addEventListener("click", () => toggleTask(task));
      actions.append(toggle);
      const cancel = document.createElement("button"); cancel.className = "text-button"; cancel.type = "button"; cancel.textContent = "移除";
      cancel.addEventListener("click", () => cancelTask(task));
      actions.append(cancel);
    }
    const bar = document.createElement("div"); bar.className = `progress${task.state === "error" ? " error" : ""}`;
    const fill = document.createElement("i"); fill.style.width = `${Math.max(0, Math.min(100, task.progress * 100))}%`; bar.append(fill);
    item.append(name, meta, actions, bar);
    return item;
  }));
}

function toggleTask(task) {
  if (task.state === "uploading") {
    task.state = "paused";
    task.detail = task.file.size >= config.large_threshold ? "已暂停，可继续" : "已暂停，继续时重新上传";
    task.abort?.abort();
  } else if (task.state === "paused" || task.state === "error") {
    task.state = "queued";
    task.detail = "等待继续";
    pump();
  }
  renderQueue();
}

async function cancelTask(task) {
  task.cancelled = true;
  task.abort?.abort();
  if (task.uploadId) {
    try { await api(`/api/uploads/${task.uploadId}`, { method: "DELETE" }); } catch (_) {}
  }
  tasks = tasks.filter(item => item !== task);
  renderQueue();
  pump();
}

async function refreshFiles() {
  const result = await api("/api/files");
  const files = result.files || [];
  emptyNode.hidden = files.length > 0;
  const total = files.reduce((sum, file) => sum + file.size, 0);
  summaryNode.textContent = files.length ? `${files.length} 项 · ${formatSize(total)}` : "";
  filesNode.replaceChildren(...files.map(renderFile));
}

function renderFile(file) {
  const row = document.createElement("div"); row.className = "file-row";
  const main = document.createElement("div"); main.className = "file-main";
  const name = document.createElement("div"); name.className = "file-name"; name.textContent = file.name; name.title = file.name;
  const checksum = document.createElement("div"); checksum.className = "file-checksum"; checksum.textContent = `sha256 ${file.checksum}`; checksum.title = file.checksum;
  main.append(name, checksum);
  const size = document.createElement("div"); size.className = "file-size"; size.textContent = formatSize(file.size);
  const stamp = document.createElement("time"); stamp.className = "file-time"; stamp.dateTime = new Date(file.created_at * 1000).toISOString(); stamp.textContent = formatTime(file.created_at);
  const actions = document.createElement("div"); actions.className = "file-actions";
  const download = document.createElement("a"); download.href = `/api/files/${file.id}/download`; download.textContent = "下载";
  const remove = document.createElement("button"); remove.type = "button"; remove.className = "delete"; remove.textContent = "删除";
  remove.addEventListener("click", async () => {
    if (!window.confirm(`删除“${file.name}”？`)) return;
    remove.disabled = true;
    try { await api(`/api/files/${file.id}`, { method: "DELETE" }); await refreshFiles(); }
    catch (error) { showToast(error.message); remove.disabled = false; }
  });
  actions.append(download, remove);
  row.append(main, size, stamp, actions);
  return row;
}

function formatSize(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / 1024 ** index;
  return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

function formatTime(epoch) {
  return new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(new Date(epoch * 1000));
}

(async function start() {
  try {
    const session = await api("/api/session");
    if (session.authenticated) await showWorkspace(session);
    else showLogin();
  } catch (error) {
    showLogin();
    loginMessage.classList.add("error");
    loginMessage.textContent = error.message;
  }
})();
