'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const rotation = require('./rotation');
const { renderPage } = require('./page');

const MAX_BODY_BYTES = 1024 * 1024;

const ERROR_STATUS = {
  unknown_domain: 404,
  unknown_rotation: 404,
  conflicting_rotation: 409,
  rotation_already_activated: 409,
  rotation_superseded: 409,
  rotation_expired: 409,
  invalid_json: 400,
  invalid_batch: 400,
};

function statusFor(code) {
  return ERROR_STATUS[code] || 422;
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(body);
}

function sendError(res, err) {
  const status = statusFor(err.code);
  sendJson(res, status, { error: { code: err.code, reason: err.message } });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new rotation.DomainError('payload_too_large', '请求体超过 1MB 上限'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function readJson(req) {
  const raw = await readBody(req);
  try {
    return raw.length === 0 ? {} : JSON.parse(raw);
  } catch {
    throw new rotation.DomainError('invalid_json', '请求体不是合法 JSON');
  }
}

/**
 * 截止时刻的剩余状态视图（仅用于展示，权威裁决仍以服务端处理时刻
 * 与串行迁移为准）。不设截止的候选 deadline 为 null。
 */
function deadlineView(rot, now) {
  if (!rot.expiresAt) return null;
  const remainingMs = Date.parse(rot.expiresAt) - Date.parse(now);
  return {
    expiresAt: rot.expiresAt,
    remainingMillis: rot.status === 'pending' ? Math.max(0, remainingMs) : 0,
    remainingSeconds: rot.status === 'pending' ? Math.max(0, Math.round(remainingMs / 1000)) : 0,
    expired: rot.status === 'expired',
  };
}

function rotationView(rot, now) {
  return {
    rotationId: rot.rotationId,
    domainId: rot.domainId,
    parentDigest: rot.parentDigest,
    generation: rot.generation,
    threshold: rot.threshold,
    keys: rot.keys,
    digest: rot.digest,
    status: rot.status,
    createdAt: rot.createdAt,
    expiresAt: rot.expiresAt,
    expiredAt: rot.expiredAt ?? null,
    deadline: deadlineView(rot, now),
    activatedAt: rot.activatedAt,
    rejectedReason: rot.rejectedReason || null,
    signers: rot.signatures.length,
    signatures: rot.signatures,
    message: rotation.authorizationMessage(rot),
  };
}

function domainSummary(domain, now) {
  const rotations = Object.values(domain.rotations);
  return {
    id: domain.id,
    name: domain.name,
    createdAt: domain.createdAt,
    generation: domain.generation,
    headDigest: domain.headDigest,
    threshold: domain.threshold,
    keys: domain.keys,
    counts: {
      pending: rotations.filter((r) => r.status === 'pending').length,
      activated: rotations.filter((r) => r.status === 'activated').length,
      superseded: rotations.filter((r) => r.status === 'superseded').length,
      expired: rotations.filter((r) => r.status === 'expired').length,
    },
  };
}

function domainDetail(domain, now) {
  return {
    ...domainSummary(domain, now),
    checkpoints: Object.values(domain.checkpoints).sort((a, b) => a.generation - b.generation),
    rotations: Object.values(domain.rotations)
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0))
      .map((r) => rotationView(r, now)),
  };
}

function createServer({ store, allowAdminRestart = false }) {
  const bootId = crypto.randomUUID();
  const startedAt = new Date().toISOString();
  const clientJs = fs.readFileSync(path.join(__dirname, 'static', 'app.js'));

  const server = http.createServer(async (req, res) => {
    try {
      await route(req, res);
    } catch (err) {
      if (err instanceof rotation.DomainError) {
        sendError(res, err);
      } else {
        console.error('[server] 未处理异常：', err);
        sendJson(res, 500, { error: { code: 'internal_error', reason: '服务器内部错误' } });
      }
    }
  });

  async function route(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const segments = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    const method = req.method;
    const nowIso = () => new Date().toISOString();

    if (method === 'GET' && segments.length === 0) {
      const now = nowIso();
      await store.settle(now);
      const body = renderPage(store.state, now);
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(body);
      return;
    }
    if (method === 'GET' && segments.length === 2 && segments[0] === 'static' && segments[1] === 'app.js') {
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store' });
      res.end(clientJs);
      return;
    }
    if (method === 'GET' && segments.length === 1 && segments[0] === 'healthz') {
      const now = nowIso();
      await store.settle(now);
      sendJson(res, 200, {
        status: 'ok',
        bootId,
        startedAt,
        serverTime: now,
        uptimeSeconds: Math.round(process.uptime() * 1000) / 1000,
        persistence: 'ok',
        domains: Object.values(store.state.domains).map((d) => domainSummary(d, now)),
      });
      return;
    }

    if (segments[0] === 'api' && segments[1] === 'domains') {
      if (method === 'GET' && segments.length === 2) {
        const now = nowIso();
        await store.settle(now);
        sendJson(res, 200, { domains: Object.values(store.state.domains).map((d) => domainSummary(d, now)) });
        return;
      }
      if (method === 'POST' && segments.length === 2) {
        const input = await readJson(req);
        const result = await store.commit((state) => rotation.createDomain(state, input, new Date().toISOString()));
        sendJson(res, 201, domainDetail(result, new Date().toISOString()));
        return;
      }
      const domainId = segments[2];
      if (method === 'GET' && segments.length === 3) {
        const now = nowIso();
        await store.settle(now);
        const domain = store.state.domains[domainId];
        if (!domain) throw new rotation.DomainError('unknown_domain', `设备域不存在：${domainId}`);
        sendJson(res, 200, domainDetail(domain, now));
        return;
      }
      if (method === 'GET' && segments.length === 4 && segments[3] === 'head') {
        const now = nowIso();
        await store.settle(now);
        const domain = store.state.domains[domainId];
        if (!domain) throw new rotation.DomainError('unknown_domain', `设备域不存在：${domainId}`);
        sendJson(res, 200, rotation.headView(domain));
        return;
      }
      if (segments.length === 4 && segments[3] === 'rotations' && method === 'POST') {
        const input = await readJson(req);
        const now = new Date().toISOString();
        const { rotation: rot, created } = await store.commit((state) =>
          rotation.createRotation(state, domainId, input, now),
        );
        sendJson(res, created ? 201 : 200, rotationView(rot, now));
        return;
      }
      if (segments.length === 6 && segments[3] === 'rotations' && segments[5] === 'message' && method === 'GET') {
        const now = nowIso();
        await store.settle(now);
        const domain = store.state.domains[domainId];
        if (!domain) throw new rotation.DomainError('unknown_domain', `设备域不存在：${domainId}`);
        const rot = domain.rotations[segments[4]];
        if (!rot) throw new rotation.DomainError('unknown_rotation', `轮换候选不存在：${segments[4]}`);
        sendJson(res, 200, {
          domainId,
          rotationId: rot.rotationId,
          digest: rot.digest,
          encoding: 'utf-8',
          status: rot.status,
          expiresAt: rot.expiresAt,
          deadline: deadlineView(rot, now),
          message: rotation.authorizationMessage(rot),
        });
        return;
      }
      if (segments.length === 6 && segments[3] === 'rotations' && segments[5] === 'signatures' && method === 'POST') {
        const input = await readJson(req);
        const result = await store.commit((state) =>
          rotation.submitSignatures(state, domainId, segments[4], input.signatures, new Date().toISOString()),
        );
        sendJson(res, 200, {
          domainId,
          rotationId: segments[4],
          activated: result.activated,
          signers: result.signers,
          threshold: result.threshold,
          headDigest: result.headDigest,
          rotationStatus: result.rotation.status,
          results: result.results,
        });
        return;
      }
    }

    if (method === 'POST' && segments.length === 3 && segments[0] === 'api' && segments[1] === 'admin' && segments[2] === 'restart') {
      if (!allowAdminRestart) {
        sendJson(res, 403, { error: { code: 'admin_disabled', reason: '未启用管理重启端点' } });
        return;
      }
      sendJson(res, 202, { ok: true, reason: '进程即将退出，由编排器按重启策略拉起，状态将从磁盘恢复' });
      setTimeout(() => process.exit(0), 150).unref();
      return;
    }

    sendJson(res, 404, { error: { code: 'not_found', reason: `未匹配的路由：${method} ${url.pathname}` } });
  }

  return server;
}

module.exports = { createServer, domainSummary, domainDetail, rotationView };
