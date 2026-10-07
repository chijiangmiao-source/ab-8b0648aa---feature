'use strict';

/* 运营页面交互：表单提交、健康状态展示、待签消息复制。 */

function parseKeys(text) {
  return text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const payload = await res.json().catch(() => null);
  if (!res.ok) {
    const err = payload && payload.error ? payload.error : { code: 'http_' + res.status, reason: res.statusText };
    throw new Error(`[${err.code}] ${err.reason}`);
  }
  return payload;
}

async function handleForm(event) {
  event.preventDefault();
  const form = event.target;
  const kind = form.dataset.kind;
  const domainId = form.dataset.domain;
  const data = new FormData(form);
  try {
    if (kind === 'domain') {
      await postJson('/api/domains', {
        name: (data.get('name') || '').toString().trim() || undefined,
        publicKeys: parseKeys((data.get('publicKeys') || '').toString()),
        threshold: Number(data.get('threshold')),
      });
    } else if (kind === 'rotation') {
      const expiresAt = (data.get('expiresAt') || '').toString().trim();
      await postJson(`/api/domains/${encodeURIComponent(domainId)}/rotations`, {
        rotationId: (data.get('rotationId') || '').toString().trim(),
        parentDigest: (data.get('parentDigest') || '').toString().trim(),
        publicKeys: parseKeys((data.get('publicKeys') || '').toString()),
        threshold: Number(data.get('threshold')),
        ...(expiresAt ? { expiresAt } : {}),
      });
    } else if (kind === 'signatures') {
      const rotationId = form.dataset.rotation;
      const signatures = JSON.parse((data.get('signatures') || '').toString());
      const result = await postJson(
        `/api/domains/${encodeURIComponent(domainId)}/rotations/${encodeURIComponent(rotationId)}/signatures`,
        { signatures },
      );
      const rejected = result.results.filter((r) => r.status === 'rejected');
      if (rejected.length > 0) {
        window.alert(
          `部分签名被拒：\n${rejected.map((r) => `- [${r.code}] ${r.reason}`).join('\n')}` +
            (result.activated ? '\n\n轮换已激活。' : ''),
        );
      } else if (result.activated) {
        window.alert('已达到父门限，轮换在同一次持久化提交中激活。');
      }
    }
    location.reload();
  } catch (err) {
    window.alert(`操作被拒绝：${err.message}`);
  }
}

async function loadHealth() {
  const box = document.getElementById('health');
  try {
    const res = await fetch('/healthz');
    const health = await res.json();
    const lines = [
      `服务状态：${health.status} · 持久化：${health.persistence} · 启动于 ${health.startedAt} · 运行 ${health.uptimeSeconds}s`,
      ...health.domains.map(
        (d) =>
          `设备域 ${d.name}（${d.id}）：链头 ${d.headDigest} · 代次 ${d.generation} · 门限 ${d.threshold}/${d.keys.length}` +
          ` · 待签 ${d.counts.pending} · 已激活 ${d.counts.activated} · 已过期 ${d.counts.expired || 0} · 已拒 ${d.counts.superseded}`,
      ),
    ];
    box.innerHTML = lines.map((l) => `<div>${l.replace(/</g, '&lt;')}</div>`).join('');
  } catch (err) {
    box.textContent = `健康检查失败：${err.message}`;
  }
}

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

/*
 * 截止剩余状态的持续展示：以页面内嵌的服务端时刻校准本地时钟偏移，
 * 每秒重算所有待签候选的剩余时间；任一候选到点后刷新页面 ——
 * 刷新本身是一次读取，服务端会在串行迁移中把候选固定为已过期。
 */
function startDeadlineTicker() {
  const marker = document.getElementById('server-time');
  if (!marker) return;
  const serverAt = Date.parse(marker.dataset.serverTime);
  if (!Number.isFinite(serverAt)) return;
  const clockOffset = serverAt - Date.now();
  const labels = document.querySelectorAll('strong.deadline[data-expires-at]');
  if (labels.length === 0) return;

  let reachedZero = false;
  const tick = () => {
    let anyZero = false;
    for (const el of labels) {
      const expiresAt = Date.parse(el.dataset.expiresAt);
      if (!Number.isFinite(expiresAt)) continue;
      const remaining = expiresAt - (Date.now() + clockOffset);
      el.textContent = formatRemaining(remaining);
      if (remaining <= 0) anyZero = true;
    }
    if (anyZero && !reachedZero) {
      reachedZero = true;
      setTimeout(() => location.reload(), 400);
    }
  };
  tick();
  setInterval(tick, 1000);
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('form.js-form').forEach((form) => form.addEventListener('submit', handleForm));
  document.querySelectorAll('button[data-copy]').forEach((btn) =>
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(btn.dataset.copy);
        btn.textContent = '已复制';
      } catch {
        window.alert('复制失败，请手动选择文本复制。');
      }
    }),
  );
  startDeadlineTicker();
  loadHealth();
});
