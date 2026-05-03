/**
 * Strict, node-aware n8n workflow credential / secret export.
 * Does not print secret values to the terminal.
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const fg = require('fast-glob');
const { stringify } = require('csv-stringify/sync');

const OWNER = 'N8n';

const CSV_HEADERS = [
  'Owner',
  'Service',
  'Account',
  'URL',
  'Username',
  'Email',
  'Phone',
  'Password',
  'Miscellaneous',
  'Notes',
];

const REVIEW_HEADERS = [...CSV_HEADERS, 'Reason'];

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const HTTP_NODE = 'n8n-nodes-base.httpRequest';
const WEBHOOK_NODE = 'n8n-nodes-base.webhook';
const SET_NODE = 'n8n-nodes-base.set';
const CODE_NODE = 'n8n-nodes-base.code';

const BLOCKED_BROAD_SCAN_TYPES = new Set([
  'n8n-nodes-base.if',
  'n8n-nodes-base.switch',
  'n8n-nodes-base.googleSheets',
  'n8n-nodes-base.gmail',
  'n8n-nodes-base.telegram',
  'n8n-nodes-base.filter',
  'n8n-nodes-base.merge',
  'n8n-nodes-base.itemLists',
]);

const INTERNAL_ID_KEYS = new Set([
  'id',
  'nodeid',
  'webhookid',
  'conditionid',
  'paireditem',
  'cachedresultname',
]);

const QUERY_SECRET_NAMES = new Set([
  'api_key',
  'apikey',
  'token',
  'access_token',
  'refresh_token',
  'client_secret',
  'password',
  'secret',
  'bearer',
]);

const HTTP_AUTH_HEADER_NAMES = new Set([
  'authorization',
  'x-api-key',
  'x-apikey',
  'api-key',
  'apikey',
  'token',
]);

const SET_NAME_SECRET_RE =
  /secret|token|api[\s_]*key|apikey|password|bearer|authorization|client_secret|access_token|refresh_token|webhook_secret|download_secret|intake_secret|delivery_secret/i;

const CODE_SECRET_PATTERNS = [
  { re: /Authorization\s*:\s*Bearer\s+([^\s'"`]+)/gi, label: 'Authorization Bearer' },
  { re: /Authorization\s*:\s*Token\s+([^\s'"`]+)/gi, label: 'Authorization Token' },
  { re: /apiKey\s*=\s*["']([^"']+)["']/gi, label: 'apiKey' },
  { re: /api_key\s*=\s*["']([^"']+)["']/gi, label: 'api_key' },
  { re: /password\s*=\s*["']([^"']+)["']/gi, label: 'password' },
  { re: /token\s*=\s*["']([^"']+)["']/gi, label: 'token' },
  { re: /client_secret\s*=\s*["']([^"']+)["']/gi, label: 'client_secret' },
];

function normalizeMode() {
  const m = (process.env.EXTRACTION_MODE || 'strict').toLowerCase().trim();
  return m === 'loose' ? 'loose' : 'strict';
}

function isUuid(value) {
  if (typeof value !== 'string') return false;
  return UUID_RE.test(value.trim());
}

function isN8nExpression(value) {
  if (typeof value !== 'string') return false;
  const t = value.trim();
  return t.startsWith('={{') && t.endsWith('}}');
}

function isLikelyPromptText(value) {
  if (typeof value !== 'string') return false;
  const t = value.trim();
  if (t.length > 6000) return true;
  const low = t.slice(0, 800).toLowerCase();
  if (
    /\byou are (a|an)\b/.test(low) &&
    t.length > 400
  ) {
    return true;
  }
  if (/\bjson schema\b/i.test(t) && t.length > 500) return true;
  if (/\btranscript\b/i.test(low) && t.length > 1200) return true;
  return false;
}

function isSecretKeyName(key) {
  if (!key || typeof key !== 'string') return false;
  const nk = key.toLowerCase().replace(/[\s-]/g, '_');
  if (SET_NAME_SECRET_RE.test(key)) return true;
  if (QUERY_SECRET_NAMES.has(nk)) return true;
  if (nk === 'key' || nk.endsWith('_key')) return true;
  return false;
}

function looksLikeEmail(s) {
  if (typeof s !== 'string' || s.length > 320) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.trim());
}

function looksLikePhone(s) {
  if (typeof s !== 'string') return false;
  const digits = s.replace(/\D/g, '');
  return digits.length >= 10 && digits.length <= 15 && /^[\d\s\-+().]+$/.test(s.trim());
}

function looksLikeHttpUrl(s) {
  if (typeof s !== 'string') return false;
  const t = s.trim();
  if (!/^https?:\/\//i.test(t)) return false;
  try {
    new URL(t);
    return true;
  } catch {
    return false;
  }
}

function isHttpAuthHeaderName(name) {
  if (!name || typeof name !== 'string') return false;
  const n = name.trim().toLowerCase();
  if (HTTP_AUTH_HEADER_NAMES.has(n)) return true;
  if (n === 'bearer' || n.startsWith('x-')) return /api|auth|key|token/.test(n);
  return false;
}

function isInternalConfigIdField(fieldName, fieldPath) {
  const fn = (fieldName || '').toString().toLowerCase();
  const fp = (fieldPath || '').toLowerCase();
  if (INTERNAL_ID_KEYS.has(fn)) return true;
  if (fn === 'webhookid' || fn === 'nodeid') return true;
  if (fp.endsWith('.id') || fp.endsWith('].id')) return true;
  if (/\.conditions\.conditions\[\d+\]\.id$/i.test(fp)) return true;
  return false;
}

function nodeNameSuggestsSecrets(node) {
  const n = (node.name || '').toLowerCase();
  return /secret|auth|token|api key|credential/.test(n);
}

function isLangchainOrOutputParser(type) {
  if (!type || typeof type !== 'string') return false;
  if (type.includes('langchain') || type.includes('LangChain')) return true;
  if (/outputparser|output_parser|chainlLm|agent/i.test(type)) return true;
  return false;
}

function isBlockedBroadScanType(type) {
  if (!type) return true;
  if (BLOCKED_BROAD_SCAN_TYPES.has(type)) return true;
  if (isLangchainOrOutputParser(type)) return true;
  return false;
}

/** Strict: only these (+ name-matched) participate in hardcoded extraction */
function isStrictHardcodedTarget(node) {
  const t = node.type || '';
  if (t === HTTP_NODE || t === WEBHOOK_NODE || t === SET_NODE || t === CODE_NODE) return true;
  if (nodeNameSuggestsSecrets(node)) return true;
  return false;
}

function setAssignmentNameIndicatesSecret(name) {
  if (!name || typeof name !== 'string') return false;
  return SET_NAME_SECRET_RE.test(name);
}

function classifyCandidate(value, fieldName, fieldPath, notesDefault) {
  if (value === null || value === undefined) return { ok: false, reason: 'empty' };
  if (typeof value === 'boolean') return { ok: false, reason: 'filtered_boolean' };
  if (typeof value === 'number') return { ok: false, reason: 'filtered_number' };
  if (typeof value !== 'string') return { ok: false, reason: 'unsupported_type' };
  const trimmed = value.trim();
  if (!trimmed) return { ok: false, reason: 'empty' };
  if (isN8nExpression(trimmed)) return { ok: false, reason: 'filtered_n8n_expression' };
  if (isUuid(trimmed)) return { ok: false, reason: 'filtered_uuid' };
  if (isInternalConfigIdField(fieldName, fieldPath)) return { ok: false, reason: 'internal_config_id' };
  if (isLikelyPromptText(trimmed)) return { ok: false, reason: 'prompt_text_or_schema' };
  if (trimmed.length < 6) return { ok: false, reason: 'low_confidence_set_node_value' };
  return { ok: true, value: trimmed, reason: null, notes: notesDefault };
}

function buildMisc({ nodeName, nodeType, workflowName, filePath, fieldPath, credId, duplicateCount }) {
  const parts = [
    `node="${nodeName}"`,
    `type="${nodeType}"`,
    `workflow="${workflowName}"`,
    `file="${path.basename(filePath)}"`,
    `path=${fieldPath}`,
  ];
  if (credId) parts.push(`credId=${credId}`);
  if (duplicateCount && duplicateCount > 1) parts.push(`duplicate_count=${duplicateCount}`);
  return parts.join('; ');
}

function credDedupKey(serviceKey, account, credId) {
  return `type:cred-ref|${serviceKey}|${account}|${credId}`;
}

function hardcodedDedupKey(service, password, notes) {
  return `type:hardcoded|${service}|${password}|${notes}`;
}

function extractWorkflowPayload(data) {
  if (!data || typeof data !== 'object') return null;
  if (Array.isArray(data.nodes)) {
    return {
      name: data.name || data.workflow?.name || '',
      nodes: data.nodes,
    };
  }
  if (data.workflow && Array.isArray(data.workflow.nodes)) {
    return {
      name: data.workflow.name || data.name || '',
      nodes: data.workflow.nodes,
    };
  }
  return null;
}

/** --- HTTP Request (strict paths only) --- */
function extractHttpRequestSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats) {
  const p = node.parameters || {};
  const nodeName = node.name || '';
  const nodeType = node.type || '';

  const pushClean = (service, password, fieldPath) => {
    stats.hardcodedRaw++;
    const notes = 'hardcoded HTTP auth/header secret';
    const key = hardcodedDedupKey(service, password, notes);
    const misc = buildMisc({
      nodeName,
      nodeType,
      workflowName,
      filePath,
      fieldPath,
      credId: '',
      duplicateCount: 1,
    });
    const row = {
      Owner: OWNER,
      Service: service || 'httpRequest',
      Account: '',
      URL: looksLikeHttpUrl(password) ? password : '',
      Username: '',
      Email: looksLikeEmail(password) ? password : '',
      Phone: looksLikePhone(password) ? password : '',
      Password: password,
      Miscellaneous: misc,
      Notes: notes,
    };
    mergeHardcodedRow(cleanAgg, key, row);
  };

  const pushReview = (reason, service, password, fieldPath) => {
    const row = {
      Owner: OWNER,
      Service: service || 'httpRequest',
      Account: '',
      URL: '',
      Username: '',
      Email: '',
      Phone: '',
      Password: password,
      Miscellaneous: buildMisc({
        nodeName,
        nodeType,
        workflowName,
        filePath,
        fieldPath,
        credId: '',
        duplicateCount: 1,
      }),
      Notes: 'hardcoded HTTP auth/header secret',
      Reason: reason,
    };
    reviewAgg.push(row);
  };

  const hp = p.headerParameters;
  if (hp && Array.isArray(hp.parameters)) {
    for (const row of hp.parameters) {
      const hname = (row.name || '').trim();
      const val = row.value;
      if (typeof val !== 'string') continue;
      const fp = `parameters.headerParameters.parameters[] (header: ${hname})`;
      if (!isHttpAuthHeaderName(hname) && !/^Bearer\s+/i.test(val.trim()) && !/^Token\s+/i.test(val.trim())) {
        continue;
      }
      const c = classifyCandidate(val, hname, fp, '');
      if (c.ok) pushClean(hname || 'header', c.value, fp);
      else if (c.reason !== 'empty') pushReview(c.reason, hname, val.slice(0, 200), fp);
    }
  }

  if (typeof p.jsonHeaders === 'string' && p.jsonHeaders.trim() && !isN8nExpression(p.jsonHeaders)) {
    try {
      const j = JSON.parse(p.jsonHeaders);
      if (j && typeof j === 'object') {
        for (const [k, v] of Object.entries(j)) {
          if (typeof v !== 'string') continue;
          if (!isSecretKeyName(k) && !isHttpAuthHeaderName(k)) continue;
          const fp = `parameters.jsonHeaders.${k}`;
          const c = classifyCandidate(v, k, fp, '');
          if (c.ok) pushClean(k, c.value, fp);
          else if (c.reason !== 'empty') pushReview(c.reason, k, String(v).slice(0, 200), fp);
        }
      }
    } catch {
      /* not JSON */
    }
  }

  const qp = p.queryParameters;
  if (qp && Array.isArray(qp.parameters)) {
    for (const row of qp.parameters) {
      const qn = (row.name || '').trim().toLowerCase().replace(/[\s-]/g, '_');
      const val = row.value;
      if (typeof val !== 'string') continue;
      const origName = (row.name || '').trim();
      const fp = `parameters.queryParameters.parameters[] (param: ${origName})`;
      const nameMatch =
        QUERY_SECRET_NAMES.has(qn) ||
        (qn === 'key' && val.trim().length >= 24);
      if (!nameMatch) continue;
      const c = classifyCandidate(val, origName, fp, '');
      if (c.ok) pushClean(origName || 'query', c.value, fp);
      else if (c.reason !== 'empty') pushReview(c.reason, origName, val.slice(0, 200), fp);
    }
  }

  const bodyCandidates = [];
  if (typeof p.jsonBody === 'string' && p.jsonBody.trim() && !isN8nExpression(p.jsonBody)) {
    try {
      const j = JSON.parse(p.jsonBody);
      if (j && typeof j === 'object') collectSecretLikeJsonKeys(j, '', bodyCandidates);
    } catch {
      /* ignore */
    }
  }
  if (p.bodyParameters && Array.isArray(p.bodyParameters.parameters)) {
    for (const row of p.bodyParameters.parameters) {
      const bn = row.name || '';
      const val = row.value;
      if (typeof val === 'string' && isSecretKeyName(bn)) {
        bodyCandidates.push({ key: bn, val, fp: `parameters.bodyParameters.parameters[] (${bn})` });
      }
    }
  }
  for (const { key, val, fp } of bodyCandidates) {
    const c = classifyCandidate(val, key, fp, '');
    if (c.ok) pushClean(key, c.value, fp);
    else if (c.reason !== 'empty') pushReview(c.reason, key, String(val).slice(0, 200), fp);
  }
}

function collectSecretLikeJsonKeys(obj, prefix, out) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return;
  for (const [k, v] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (typeof v === 'string' && isSecretKeyName(k)) {
      out.push({ key: k, val: v, fp: `parameters.jsonBody.${path}` });
    } else if (v && typeof v === 'object' && !Array.isArray(v)) {
      collectSecretLikeJsonKeys(v, path, out);
    }
  }
}

/** --- Webhook: header auth blocks only --- */
function extractWebhookSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats) {
  const p = node.parameters || {};
  const nodeName = node.name || '';
  const nodeType = node.type || '';

  const authentication = p.authentication;
  if (!authentication || typeof authentication !== 'object') return;

  const pushClean = (service, password, fieldPath) => {
    stats.hardcodedRaw++;
    const notes = 'hardcoded HTTP auth/header secret';
    const key = hardcodedDedupKey(service, password, notes);
    const row = {
      Owner: OWNER,
      Service: service || 'webhook',
      Account: '',
      URL: looksLikeHttpUrl(password) ? password : '',
      Username: '',
      Email: looksLikeEmail(password) ? password : '',
      Phone: looksLikePhone(password) ? password : '',
      Password: password,
      Miscellaneous: buildMisc({
        nodeName,
        nodeType,
        workflowName,
        filePath,
        fieldPath,
        credId: '',
        duplicateCount: 1,
      }),
      Notes: notes,
    };
    mergeHardcodedRow(cleanAgg, key, row);
  };

  const pushReview = (reason, service, password, fieldPath) => {
    reviewAgg.push({
      Owner: OWNER,
      Service: service || 'webhook',
      Account: '',
      URL: '',
      Username: '',
      Email: '',
      Phone: '',
      Password: password.slice(0, 200),
      Miscellaneous: buildMisc({
        nodeName,
        nodeType,
        workflowName,
        filePath,
        fieldPath,
        credId: '',
        duplicateCount: 1,
      }),
      Notes: 'hardcoded HTTP auth/header secret',
      Reason: reason,
    });
  };

  for (const [k, v] of Object.entries(authentication)) {
    if (typeof v !== 'string') continue;
    const fp = `parameters.authentication.${k}`;
    if (!isSecretKeyName(k) && !isHttpAuthHeaderName(k)) continue;
    const c = classifyCandidate(v, k, fp, '');
    if (c.ok) pushClean(k, c.value, fp);
    else if (c.reason !== 'empty') pushReview(c.reason, k, v, fp);
  }

}

/** --- Set node: named assignments only --- */
function extractSetNodeSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats) {
  const p = node.parameters || {};
  const assigns = p.assignments?.assignments;
  if (!Array.isArray(assigns)) return;
  const nodeName = node.name || '';
  const nodeType = node.type || '';

  for (let i = 0; i < assigns.length; i++) {
    const a = assigns[i];
    const fieldName = a.name != null ? String(a.name) : '';
    const val = a.value;
    const fp = `parameters.assignments.assignments[${i}].value`;
    if (!setAssignmentNameIndicatesSecret(fieldName)) {
      if (
        typeof val === 'string' &&
        val.trim().length > 32 &&
        !isN8nExpression(val) &&
        !isUuid(val.trim())
      ) {
        reviewAgg.push({
          Owner: OWNER,
          Service: 'set',
          Account: '',
          URL: '',
          Username: '',
          Email: '',
          Phone: '',
          Password: val.slice(0, 200),
          Miscellaneous: buildMisc({
            nodeName,
            nodeType,
            workflowName,
            filePath,
            fieldPath: `${fp} (field name: ${fieldName})`,
            credId: '',
            duplicateCount: 1,
          }),
          Notes: 'explicit Set node secret',
          Reason: 'low_confidence_set_node_value',
        });
      }
      continue;
    }
    if (typeof val !== 'string') continue;
    const c = classifyCandidate(val, fieldName, fp, '');
    const notes = 'explicit Set node secret';
    if (c.ok) {
      stats.hardcodedRaw++;
      const key = hardcodedDedupKey(fieldName, c.value, notes);
      const row = {
        Owner: OWNER,
        Service: 'set',
        Account: '',
        URL: looksLikeHttpUrl(c.value) ? c.value : '',
        Username: '',
        Email: looksLikeEmail(c.value) ? c.value : '',
        Phone: looksLikePhone(c.value) ? c.value : '',
        Password: c.value,
        Miscellaneous: buildMisc({
          nodeName,
          nodeType,
          workflowName,
          filePath,
          fieldPath: `${fp} (field name: ${fieldName})`,
          credId: '',
          duplicateCount: 1,
        }),
        Notes: notes,
      };
      mergeHardcodedRow(cleanAgg, key, row);
    } else if (c.reason !== 'empty') {
      reviewAgg.push({
        Owner: OWNER,
        Service: 'set',
        Account: '',
        URL: '',
        Username: '',
        Email: '',
        Phone: '',
        Password: val.slice(0, 200),
        Miscellaneous: buildMisc({
          nodeName,
          nodeType,
          workflowName,
          filePath,
          fieldPath: `${fp} (field name: ${fieldName})`,
          credId: '',
          duplicateCount: 1,
        }),
        Notes: notes,
        Reason: c.reason,
      });
    }
  }
}

/** --- Code node: regex-only --- */
function extractCodeNodeSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats) {
  const code = node.parameters?.jsCode;
  if (typeof code !== 'string' || !code.trim()) return;
  const nodeName = node.name || '';
  const nodeType = node.type || '';
  const seen = new Set();

  for (const { re, label } of CODE_SECRET_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code)) !== null) {
      const cap = m[1];
      if (!cap || seen.has(cap)) continue;
      seen.add(cap);
      const fp = `parameters.jsCode (pattern: ${label})`;
      const c = classifyCandidate(cap, label, fp, '');
      const notes = 'hardcoded password/token';
      if (c.ok) {
        stats.hardcodedRaw++;
        const key = hardcodedDedupKey(`code:${label}`, c.value, notes);
        const row = {
          Owner: OWNER,
          Service: 'code',
          Account: '',
          URL: looksLikeHttpUrl(c.value) ? c.value : '',
          Username: '',
          Email: looksLikeEmail(c.value) ? c.value : '',
          Phone: looksLikePhone(c.value) ? c.value : '',
          Password: c.value,
          Miscellaneous: buildMisc({
            nodeName,
            nodeType,
            workflowName,
            filePath,
            fieldPath: fp,
            credId: '',
            duplicateCount: 1,
          }),
          Notes: notes,
        };
        mergeHardcodedRow(cleanAgg, key, row);
      } else if (c.reason !== 'empty') {
        reviewAgg.push({
          Owner: OWNER,
          Service: 'code',
          Account: '',
          URL: '',
          Username: '',
          Email: '',
          Phone: '',
          Password: String(cap).slice(0, 200),
          Miscellaneous: buildMisc({
            nodeName,
            nodeType,
            workflowName,
            filePath,
            fieldPath: fp,
            credId: '',
            duplicateCount: 1,
          }),
          Notes: notes,
          Reason: c.reason,
        });
      }
    }
  }
}

function mergeHardcodedRow(agg, key, row) {
  if (!agg.has(key)) {
    agg.set(key, { row: { ...row }, count: 1 });
    return;
  }
  agg.get(key).count += 1;
}

function extractHttpLikeForNamedNode(node, workflowName, filePath, cleanAgg, reviewAgg, stats) {
  extractHttpRequestSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats);
}

/** --- Loose broad walk (filtered) --- */
function walkLooseParameters(obj, pathParts, node, workflowName, filePath, cleanAgg, reviewAgg, stats) {
  if (obj === null || obj === undefined) return;
  const tail = pathParts.join('.');
  const pathStr = tail ? `parameters.${tail}` : 'parameters';

  if (typeof obj === 'string') {
    const lastKey = pathParts[pathParts.length - 1] || '';
    if (isInternalConfigIdField(lastKey, pathStr)) {
      return;
    }
    const c = classifyCandidate(obj, lastKey, pathStr, '');
    if (c.ok && (isSecretKeyName(lastKey) || /^Bearer\s+/i.test(c.value))) {
      stats.hardcodedRaw++;
      const notes = 'hardcoded password/token';
      const key = hardcodedDedupKey(`${lastKey}`, c.value, notes);
      const row = {
        Owner: OWNER,
        Service: serviceFromNodeType(node.type),
        Account: '',
        URL: looksLikeHttpUrl(c.value) ? c.value : '',
        Username: '',
        Email: looksLikeEmail(c.value) ? c.value : '',
        Phone: looksLikePhone(c.value) ? c.value : '',
        Password: c.value,
        Miscellaneous: buildMisc({
          nodeName: node.name,
          nodeType: node.type,
          workflowName,
          filePath,
          fieldPath: pathStr,
          credId: '',
          duplicateCount: 1,
        }),
        Notes: notes,
      };
      mergeHardcodedRow(cleanAgg, key, row);
    } else if (!c.ok && c.reason !== 'empty' && typeof obj === 'string' && obj.trim().length > 28) {
      if (isSecretKeyName(lastKey) || /secret|token|password|auth/i.test(lastKey)) {
        reviewAgg.push({
          Owner: OWNER,
          Service: serviceFromNodeType(node.type),
          Account: '',
          URL: '',
          Username: '',
          Email: '',
          Phone: '',
          Password: obj.slice(0, 200),
          Miscellaneous: buildMisc({
            nodeName: node.name,
            nodeType: node.type,
            workflowName,
            filePath,
            fieldPath: pathStr,
            credId: '',
            duplicateCount: 1,
          }),
          Notes: 'hardcoded password/token',
          Reason: c.reason,
        });
      }
    }
    return;
  }

  if (typeof obj !== 'object') return;

  if (Array.isArray(obj)) {
    obj.forEach((item, i) => {
      walkLooseParameters(item, [...pathParts, `[${i}]`], node, workflowName, filePath, cleanAgg, reviewAgg, stats);
    });
    return;
  }

  for (const [k, v] of Object.entries(obj)) {
    if (k === 'jsCode' && node.type !== CODE_NODE) continue;
    walkLooseParameters(v, [...pathParts, k], node, workflowName, filePath, cleanAgg, reviewAgg, stats);
  }
}

function serviceFromNodeType(nodeType) {
  if (!nodeType || typeof nodeType !== 'string') return 'unknown';
  const m = nodeType.match(/n8n-nodes-base\.(.+)/);
  return m ? m[1] : nodeType;
}

function mergeCredentialRow(credAgg, key, row) {
  if (!credAgg.has(key)) {
    credAgg.set(key, { row: { ...row }, count: 1 });
    return;
  }
  credAgg.get(key).count += 1;
}

function processWorkflowFile(filePath, mode, credAgg, cleanAgg, reviewAgg, stats) {
  let text;
  try {
    text = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    console.warn(`Failed to read file: ${filePath}`, e.message);
    stats.filesFailedRead++;
    return;
  }

  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    console.warn(`Failed to parse JSON: ${filePath}`);
    stats.filesParseFailed++;
    return;
  }

  const payload = extractWorkflowPayload(data);
  if (!payload) {
    stats.filesNotWorkflow++;
    return;
  }

  stats.filesParsed++;
  stats.workflowsParsed++;
  const workflowName = payload.name || '';

  for (const node of payload.nodes || []) {
    if (!node || typeof node !== 'object') continue;

    if (node.credentials && typeof node.credentials === 'object') {
      for (const [serviceKey, credObj] of Object.entries(node.credentials)) {
        if (!credObj || typeof credObj !== 'object') continue;
        const account = credObj.name != null ? String(credObj.name) : '';
        const credId = credObj.id != null ? String(credObj.id) : '';
        stats.credentialRefsRaw++;
        const key = credDedupKey(serviceKey, account, credId);
        const fieldPath = `credentials.${serviceKey}`;
        const row = {
          Owner: OWNER,
          Service: serviceKey,
          Account: account,
          URL: '',
          Username: '',
          Email: looksLikeEmail(account) ? account : '',
          Phone: '',
          Password: '',
          Miscellaneous: buildMisc({
            nodeName: node.name || '',
            nodeType: node.type || '',
            workflowName,
            filePath,
            fieldPath,
            credId,
            duplicateCount: 1,
          }),
          Notes: 'n8n credential reference',
        };
        mergeCredentialRow(credAgg, key, row);
      }
    }

    const t = node.type || '';

    if (mode === 'strict') {
      if (!isStrictHardcodedTarget(node)) {
        continue;
      }
      if (t === HTTP_NODE) {
        extractHttpRequestSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats);
      } else if (t === WEBHOOK_NODE) {
        extractWebhookSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats);
      } else if (t === SET_NODE) {
        extractSetNodeSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats);
      } else if (t === CODE_NODE) {
        extractCodeNodeSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats);
      } else if (nodeNameSuggestsSecrets(node)) {
        extractHttpLikeForNamedNode(node, workflowName, filePath, cleanAgg, reviewAgg, stats);
      }
      continue;
    }

    // loose mode
    if (isBlockedBroadScanType(t)) {
      continue;
    }
    if (t === HTTP_NODE) {
      extractHttpRequestSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats);
    } else if (t === WEBHOOK_NODE) {
      extractWebhookSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats);
    } else if (t === SET_NODE) {
      extractSetNodeSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats);
    } else if (t === CODE_NODE) {
      extractCodeNodeSecrets(node, workflowName, filePath, cleanAgg, reviewAgg, stats);
    }
    const specialized = new Set([HTTP_NODE, WEBHOOK_NODE, SET_NODE, CODE_NODE]);
    if (node.parameters && !specialized.has(t)) {
      walkLooseParameters(node.parameters, [], node, workflowName, filePath, cleanAgg, reviewAgg, stats);
    }
  }
}

function finalizeCredRows(credAgg) {
  const rows = [];
  for (const { row, count } of credAgg.values()) {
    let misc = row.Miscellaneous;
    if (count > 1) {
      misc = `${misc}; duplicate_count=${count}`;
    }
    rows.push({ ...row, Miscellaneous: misc });
  }
  return rows;
}

function finalizeHardcodedRows(cleanAgg) {
  const rows = [];
  for (const { row, count } of cleanAgg.values()) {
    let misc = row.Miscellaneous;
    if (count > 1) {
      misc = `${misc}; duplicate_count=${count}`;
    }
    rows.push({ ...row, Miscellaneous: misc });
  }
  return rows;
}

function main() {
  const rawDir = process.env.N8N_WORKFLOWS_DIR;
  const rawClean = process.env.OUTPUT_CSV || './n8n-credentials-clean.csv';
  const rawReview = process.env.REVIEW_CSV || './n8n-credentials-review.csv';
  const mode = normalizeMode();

  if (!rawDir || !String(rawDir).trim()) {
    console.error('Missing N8N_WORKFLOWS_DIR. Copy .env.example to .env and set N8N_WORKFLOWS_DIR.');
    process.exit(1);
  }

  const workflowsDir = path.resolve(process.cwd(), rawDir);
  const outputClean = path.resolve(process.cwd(), rawClean);
  const outputReview = path.resolve(process.cwd(), rawReview);

  if (!fs.existsSync(workflowsDir)) {
    console.error(`Workflow directory does not exist: ${workflowsDir}`);
    process.exit(1);
  }

  const pattern = path.join(workflowsDir, '**/*.json').replace(/\\/g, '/');
  const files = fg.sync(pattern, { onlyFiles: true, absolute: true });

  const credAgg = new Map();
  const cleanAgg = new Map();
  const reviewAgg = [];

  const stats = {
    filesScanned: files.length,
    filesParsed: 0,
    filesParseFailed: 0,
    filesFailedRead: 0,
    filesNotWorkflow: 0,
    workflowsParsed: 0,
    credentialRefsRaw: 0,
    hardcodedRaw: 0,
  };

  for (const filePath of files) {
    processWorkflowFile(filePath, mode, credAgg, cleanAgg, reviewAgg, stats);
  }

  const credRows = finalizeCredRows(credAgg);
  const hardRows = finalizeHardcodedRows(cleanAgg);

  const uniqueCredExported = credRows.length;
  const hardcodedExported = hardRows.length;
  const duplicatesRemoved =
    stats.credentialRefsRaw -
    uniqueCredExported +
    (stats.hardcodedRaw - hardcodedExported);

  for (const dir of [path.dirname(outputClean), path.dirname(outputReview)]) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(
    outputClean,
    stringify([...credRows, ...hardRows], {
      header: true,
      columns: CSV_HEADERS,
      quoted_string: true,
    }),
    'utf8',
  );

  fs.writeFileSync(
    outputReview,
    stringify(reviewAgg, {
      header: true,
      columns: REVIEW_HEADERS,
      quoted_string: true,
    }),
    'utf8',
  );

  console.log('--- n8n credentials export summary ---');
  console.log(`EXTRACTION_MODE:       ${mode}`);
  console.log(`JSON files scanned:    ${stats.filesScanned}`);
  console.log(`Workflows parsed:      ${stats.workflowsParsed}`);
  console.log(`JSON parse failures:   ${stats.filesParseFailed}`);
  console.log(`Non-workflow JSON:     ${stats.filesNotWorkflow}`);
  console.log(`Credential refs found: ${stats.credentialRefsRaw}`);
  console.log(`Unique cred refs out:  ${uniqueCredExported}`);
  console.log(`Hardcoded found:       ${stats.hardcodedRaw}`);
  console.log(`Hardcoded exported:    ${hardcodedExported}`);
  console.log(`Review rows written:   ${reviewAgg.length}`);
  console.log(`Duplicates removed:    ${duplicatesRemoved}`);
  console.log(`Clean CSV:             ${outputClean}`);
  console.log(`Review CSV:            ${outputReview}`);
}

main();
