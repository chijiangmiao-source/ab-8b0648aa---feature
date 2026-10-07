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
  invalid_deadline: 400,
  invalid_json: 400,
  invalid_batch: 400,
};

function statusFor(code) {
  return ERROR_STATUS[code] || 422;
}

function nowIso() {
  return new Date().toISOString();
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

function rotationView(rot, now = new Date().toISOString()) {
  const view = {
    rotationId: rot.rotationId,
    domainId: rot.domainId,
    parentDigest: rot.parentDigest,
    generation: rot.generation,
    threshold: rot.threshold,
    keys: rot.keys,
    digest: rot.digest,
    status: rot.status,
    createdAt: rot.createdAt,
    activatedAt: rot.activatedAt,
    expiredAt: rot.expiredAt || null,
    deadline: rot.deadline ?? null,
    rejectedReason: rot.rejectedReason || null,
    signers: rot.signatures.length,
    signatures: rot.signatures,
    message: rotation.authorizationMessage(rot),
  };
  if (rot.deadline) {
    const remainingMs = Date.parse(rot.deadline) - Date.parse(now);
    view.remainingMs = remainingMs;
    // pending 且仍在窗口内才算剩余；已过期固定后以 status=expired 为准。
    view.windowOpen = rot.status === 'pending' && remainingMs > 0;
  }
  return view;
}

function domainSummary(domain) {
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

function domainDetail(domain) {
  // 视图在读取时裁决剩余状态：以当前时刻计算每个候选的剩余毫秒数。
  const now = new Date().toISOString();
  return {
    ...domainSummary(domain),
    observedAt: now,
    checkpoints: Object.values(domain.checkpoints).sort((a, b) => a.generation - b.generation),
    rotations: Object.values(domain.rotations)
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0))
      .map((rot) => rotationView(rot, now)),
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

    // 读取驱动的过期固定：页面/接口读取前，在串行队列中裁决所有已过截止时刻的待签候选。
    const sweepAll = () =>
      store.commit((state) => ({ state: rotation.sweepAllExpired(state, new Date().toISOString()), result: null }));
    const sweepDomain = (domainId) =>
      store.commit((state) => ({ state: rotation.sweepExpiredRotations(state, domainId, new Date().toISOString()), result: null }));

    if (method === 'GET' && segments.length === 0) {
      await sweepAll();
      const body = renderPage(store.state);
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
      await sweepAll();
      sendJson(res, 200, {
        status: 'ok',
        bootId,
        startedAt,
        uptimeSeconds: Math.round(process.uptime() * 1000) / 1000,
        persistence: 'ok',
        observedAt: new Date().toISOString(),
        domains: Object.values(store.state.domains).map(domainSummary),
      });
      return;
    }

    if (segments[0] === 'api' && segments[1] === 'domains') {
      if (method === 'GET' && segments.length === 2) {
        await sweepAll();
        sendJson(res, 200, { domains: Object.values(store.state.domains).map(domainSummary) });
        return;
      }
      if (method === 'POST' && segments.length === 2) {
        const input = await readJson(req);
        const result = await store.commit((state) => rotation.createDomain(state, input, nowIso()));
        sendJson(res, 201, domainDetail(result));
        return;
      }
      const domainId = segments[2];
      if (method === 'GET' && segments.length === 3) {
        await sweepDomain(domainId);
        const domain = store.state.domains[domainId];
        if (!domain) throw new rotation.DomainError('unknown_domain', `设备域不存在：${domainId}`);
        sendJson(res, 200, domainDetail(domain));
        return;
      }
      if (method === 'GET' && segments.length === 4 && segments[3] === 'head') {
        await sweepDomain(domainId);
        const domain = store.state.domains[domainId];
        if (!domain) throw new rotation.DomainError('unknown_domain', `设备域不存在：${domainId}`);
        sendJson(res, 200, rotation.headView(domain));
        return;
      }
      if (segments.length === 4 && segments[3] === 'rotations' && method === 'POST') {
        const input = await readJson(req);
        // now 在迁移真正排空执行时给出（串行处理时刻），而非请求到达时刻。
        const { rotation: rot, created } = await store.commit((state) =>
          rotation.createRotation(state, domainId, input, new Date().toISOString()),
        );
        sendJson(res, created ? 201 : 200, rotationView(rot, new Date().toISOString()));
        return;
      }
      if (segments.length === 6 && segments[3] === 'rotations' && segments[5] === 'message' && method === 'GET') {
        await sweepDomain(domainId);
        const domain = store.state.domains[domainId];
        if (!domain) throw new rotation.DomainError('unknown_domain', `设备域不存在：${domainId}`);
        const rot = domain.rotations[segments[4]];
        if (!rot) throw new rotation.DomainError('unknown_rotation', `轮换候选不存在：${segments[4]}`);
        sendJson(res, 200, {
          domainId,
          rotationId: rot.rotationId,
          digest: rot.digest,
          encoding: 'utf-8',
          deadline: rot.deadline ?? null,
          status: rot.status,
          message: rotation.authorizationMessage(rot),
        });
        return;
      }
      if (segments.length === 6 && segments[3] === 'rotations' && segments[5] === 'signatures' && method === 'POST') {
        const input = await readJson(req);
        // 截止时刻以“处理签名的时刻”裁决：时钟在串行队列排空执行迁移时读取。
        const outcome = await store.commit((state) =>
          rotation.submitSignatures(state, domainId, segments[4], input.signatures, new Date().toISOString()),
        );
        // 截止后首次补签：迁移已把候选持久化为 expired，本次请求返回稳定拒因。
        if (outcome && outcome.rejected) {
          throw outcome.rejection;
        }
        sendJson(res, 200, {
          domainId,
          rotationId: segments[4],
          activated: outcome.activated,
          signers: outcome.signers,
          threshold: outcome.threshold,
          headDigest: outcome.headDigest,
          rotationStatus: outcome.rotation.status,
          results: outcome.results,
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
