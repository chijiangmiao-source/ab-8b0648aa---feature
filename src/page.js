'use strict';

/** 服务端渲染的运营页面：链头、检查点分组、签名证据与操作表单。 */

const rotation = require('./rotation');

function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/** 剩余时间的人类可读形式（由页面脚本每秒按同一口径重算）。 */
function formatRemaining(ms) {
  if (ms <= 0) return '已到截止时刻';
  const totalSeconds = Math.ceil(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const parts = [];
  if (hours > 0) parts.push(`${hours} 小时`);
  if (minutes > 0) parts.push(`${minutes} 分`);
  parts.push(`${seconds} 秒`);
  return `剩余 ${parts.join(' ')}`;
}

function keyList(keys) {
  return `<ul class="keys">${keys.map((k) => `<li><code>${esc(k)}</code></li>`).join('')}</ul>`;
}

function evidenceList(evidence) {
  if (!evidence || evidence.length === 0) return '<p class="muted">（创世检查点，无签名证据）</p>';
  return `<ul class="evidence">${evidence
    .map(
      (e) =>
        `<li>签名者 <code>${esc(e.publicKey)}</code><br>签名 <code>${esc(e.signature)}</code><br>` +
        `<span class="muted">接收于 ${esc(e.receivedAt)}</span></li>`,
    )
    .join('')}</ul>`;
}

function renderCheckpoint(cp) {
  return `<div class="checkpoint">
    <p>代次 <strong>${cp.generation}</strong> · 摘要 <code>${esc(cp.digest)}</code></p>
    <p>轮换标识 <code>${esc(cp.rotationId)}</code> · 父摘要 <code>${esc(cp.parentDigest)}</code></p>
    <p>门限 <strong>${cp.threshold}</strong> / ${cp.keys.length} · 激活于 ${esc(cp.activatedAt)}</p>
    <details><summary>密钥集（排序后，${cp.keys.length} 把）</summary>${keyList(cp.keys)}</details>
    <details><summary>签名证据（${cp.evidence.length} 份）</summary>${evidenceList(cp.evidence)}</details>
  </div>`;
}

function renderPendingRotation(domain, rot, now) {
  const message = rotation.authorizationMessage(rot);
  let deadlineHtml = '<p class="muted">未设置截止时刻：保持补签直至达到父门限</p>';
  if (rot.expiresAt) {
    const remainingMs = Date.parse(rot.expiresAt) - Date.parse(now);
    deadlineHtml = `<p>UTC 截止时刻 <code>${esc(rot.expiresAt)}</code>
      · <strong class="deadline" data-expires-at="${esc(rot.expiresAt)}">${esc(formatRemaining(remainingMs))}</strong></p>`;
  }
  return `<div class="checkpoint pending">
    <p>轮换标识 <code>${esc(rot.rotationId)}</code> · 状态 <strong class="pending">待签</strong></p>
    <p>固定父摘要 <code>${esc(rot.parentDigest)}</code> · 下一代次 <strong>${rot.generation}</strong></p>
    <p>候选摘要 <code>${esc(rot.digest)}</code> · 新门限 <strong>${rot.threshold}</strong> / ${rot.keys.length}</p>
    ${deadlineHtml}
    <details open><summary>排序后新公钥集（${rot.keys.length} 把）</summary>${keyList(rot.keys)}</details>
    <p>已收集签名 <strong>${rot.signatures.length}</strong> / 父门限 ${domain.threshold}
       <span class="muted">（须在截止前达到父门限方可激活）</span></p>
    <details><summary>已收签名明细</summary>${evidenceList(rot.signatures)}</details>
    <details><summary>规范待签消息（UTF-8，交由父密钥成员离线签名）</summary><pre class="message">${esc(message)}</pre>
      <button type="button" data-copy="${esc(message)}">复制待签消息</button></details>
    <form class="js-form" data-kind="signatures" data-domain="${esc(domain.id)}" data-rotation="${esc(rot.rotationId)}">
      <label>提交签名批次（JSON 数组：[{"publicKey":"…","signature":"…"}]）
        <textarea name="signatures" rows="4" required placeholder='[{"publicKey":"64位hex","signature":"128位hex"}]'></textarea>
      </label>
      <button type="submit">提交签名批次</button>
    </form>
  </div>`;
}

function renderSupersededRotation(rot) {
  return `<div class="checkpoint superseded">
    <p>轮换标识 <code>${esc(rot.rotationId)}</code> · 状态 <strong class="superseded">已拒</strong></p>
    <p>固定父摘要 <code>${esc(rot.parentDigest)}</code> · 代次 ${rot.generation} · 候选摘要 <code>${esc(rot.digest)}</code></p>
    <p>拒因：${esc(rot.rejectedReason || '')}</p>
  </div>`;
}

function renderExpiredRotation(rot) {
  const collected = rot.signatures.length;
  return `<div class="checkpoint expired">
    <p>轮换标识 <code>${esc(rot.rotationId)}</code> · 状态 <strong class="expired">已过期</strong></p>
    <p>固定父摘要 <code>${esc(rot.parentDigest)}</code> · 代次 ${rot.generation} · 候选摘要 <code>${esc(rot.digest)}</code></p>
    <p>UTC 截止时刻 <code>${esc(rot.expiresAt)}</code> · 固化于 ${esc(rot.expiredAt || '')}
       · 截止前仅收集 <strong>${collected}</strong> 份去重签名，未达父门限</p>
    <p>原因：${esc(rot.rejectedReason || '')}</p>
    <details><summary>已收签名明细（${collected} 份，不作为激活证据）</summary>${evidenceList(rot.signatures)}</details>
  </div>`;
}

function renderDomain(domain, now) {
  const rotations = Object.values(domain.rotations).sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1));
  const pending = rotations.filter((r) => r.status === 'pending');
  const superseded = rotations.filter((r) => r.status === 'superseded');
  const expired = rotations.filter((r) => r.status === 'expired');
  const checkpoints = Object.values(domain.checkpoints).sort((a, b) => a.generation - b.generation);

  return `<article class="domain" id="domain-${esc(domain.id)}">
    <h3>${esc(domain.name)} <small><code>${esc(domain.id)}</code></small></h3>
    <p>当前链头 <code class="head">${esc(domain.headDigest)}</code> · 代次 <strong>${domain.generation}</strong>
       · 门限 <strong>${domain.threshold}</strong> / ${domain.keys.length}</p>
    <details><summary>当前密钥集（排序后）</summary>${keyList(domain.keys)}</details>

    <h4>已激活检查点链</h4>
    ${checkpoints.map(renderCheckpoint).join('')}

    <h4>待签候选（${pending.length}）</h4>
    ${pending.length ? pending.map((r) => renderPendingRotation(domain, r, now)).join('') : '<p class="muted">无</p>'}

    <h4>已过期候选（${expired.length}）</h4>
    ${expired.length ? expired.map(renderExpiredRotation).join('') : '<p class="muted">无</p>'}

    <h4>已拒候选（${superseded.length}）</h4>
    ${superseded.length ? superseded.map(renderSupersededRotation).join('') : '<p class="muted">无</p>'}

    <details class="new-rotation">
      <summary>为此设备域创建轮换候选</summary>
      <form class="js-form" data-kind="rotation" data-domain="${esc(domain.id)}">
        <label>轮换标识 <input name="rotationId" required pattern="[A-Za-z0-9][A-Za-z0-9._-]*" maxlength="128" placeholder="rot-2026-001"></label>
        <label>固定父摘要（当前链头，不可改） <input name="parentDigest" value="${esc(domain.headDigest)}" readonly></label>
        <label>新公钥集（每行一把 64 位十六进制 Ed25519 公钥，2–5 把）
          <textarea name="publicKeys" rows="4" required></textarea></label>
        <label>新门限 <input name="threshold" type="number" min="1" max="5" value="2" required></label>
        <label>UTC 截止时刻（可选，留空表示不设截止；如 2026-10-07T12:00:00Z）
          <input name="expiresAt" type="text" placeholder="2026-10-07T12:00:00Z"></label>
        <button type="submit">创建轮换候选</button>
      </form>
    </details>
  </article>`;
}

function renderPage(state, now) {
  const renderAt = now || new Date().toISOString();
  const domains = Object.values(state.domains).sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1));
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>隔离维护网 · 设备域密钥轮换</title>
<style>
  body { font-family: system-ui, "PingFang SC", "Microsoft YaHei", sans-serif; margin: 2rem auto; max-width: 1080px; padding: 0 1rem; color: #1c2530; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85em; word-break: break-all; }
  h1 { border-bottom: 3px solid #14532d; padding-bottom: .4rem; }
  .domain { border: 1px solid #cbd5e1; border-radius: 8px; padding: 1rem 1.25rem; margin: 1.25rem 0; background: #fff; }
  .checkpoint { border-left: 4px solid #16a34a; background: #f0fdf4; padding: .5rem .9rem; margin: .6rem 0; }
  .checkpoint.pending { border-color: #d97706; background: #fffbeb; }
  .checkpoint.superseded { border-color: #dc2626; background: #fef2f2; }
  .checkpoint.expired { border-color: #7c3aed; background: #f5f3ff; }
  .pending { color: #b45309; } .superseded { color: #b91c1c; } .expired { color: #6d28d9; }
  .deadline { color: #b45309; white-space: nowrap; }
  .keys li, .evidence li { margin: .25rem 0; }
  .message { background: #0f172a; color: #e2e8f0; padding: .75rem; border-radius: 6px; white-space: pre-wrap; }
  form label { display: block; margin: .5rem 0; }
  input, textarea { width: 100%; box-sizing: border-box; font-family: inherit; padding: .35rem; }
  button { margin: .4rem 0; padding: .45rem 1rem; cursor: pointer; }
  .muted { color: #64748b; }
  #health { border: 1px dashed #94a3b8; padding: .6rem .9rem; border-radius: 8px; background: #f8fafc; }
  .head { background: #dcfce7; padding: 0 .3rem; border-radius: 4px; }
</style>
</head>
<body>
<h1>隔离维护网 · 设备域命令签发密钥轮换</h1>
<p class="muted">唯一授权链：新密钥只有在去重后的父密钥成员签名达到父门限时，才会在同一次持久化提交中激活；
延迟签名、重复重传与竞争候选都不会让新密钥提前生效。候选可设置可选的 UTC 截止时刻：
截止前达到父门限才可激活，截止后首次补签或读取会把未激活候选固定为已过期。</p>

<section id="health">健康状态：加载中…</section>

<section>
  <h2>创建设备域</h2>
  <form class="js-form" data-kind="domain">
    <label>名称 <input name="name" maxlength="80" placeholder="泵站-A 控制域"></label>
    <label>Ed25519 公钥（每行一把，64 位十六进制，2–5 把）
      <textarea name="publicKeys" rows="4" required></textarea></label>
    <label>门限 <input name="threshold" type="number" min="1" max="5" value="2" required></label>
    <button type="submit">创建设备域</button>
  </form>
</section>

<section>
  <h2>设备域（${domains.length}） <button type="button" onclick="location.reload()">刷新</button></h2>
  ${domains.length ? domains.map((d) => renderDomain(d, renderAt)).join('\n') : '<p class="muted">尚未创建任何设备域。</p>'}
</section>

<span id="server-time" data-server-time="${esc(renderAt)}" hidden></span>
<script src="/static/app.js"></script>
</body>
</html>`;
}

module.exports = { renderPage };
