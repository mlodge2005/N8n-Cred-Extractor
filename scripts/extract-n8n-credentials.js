/**
 * Recursively scans n8n workflow JSON exports for credential references
 * and hardcoded secret-like values. Writes CSV; does not print secrets.
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

/** Keys / path segments that usually hold non-secret prose */
const SKIP_VALUE_SCAN_KEYS = new Set([
  'jsCode',
  'systemMessage',
  'systemmessage',
  'text',
  'message',
  'messages',
  'prompt',
  'description',
  'content',
  'html',
  'markdown',
]);

const SECRET_KEY_SUBSTRINGS = [
  'secret',
  'token',
  'api_key',
  'apikey',
  'password',
  'authorization',
  'bearer',
  'client_secret',
  'access_token',
  'refresh_token',
  'private_key',
  'webhook_secret',
  'download_secret',
  'intake_secret',
  'delivery_secret',
  'x-api-key',
  'x_api_key',
];

function normalizeKeySegment(key) {
  return String(key).toLowerCase().replace(/[\s-]/g, '_');
}

function isSecretLikeKey(key) {
  if (!key || typeof key !== 'string') return false;
  const nk = normalizeKeySegment(key);
  for (const s of SECRET_KEY_SUBSTRINGS) {
    if (nk.includes(s.replace(/-/g, '_'))) return true;
  }
  if (nk === 'auth' || nk.endsWith('_auth') || nk.startsWith('auth_')) return true;
  if (nk.includes('authorization')) return true;
  if (nk.includes('pass') && (nk.includes('password') || nk.includes('passphrase') || nk.includes('passwd'))) return true;
  if (nk === 'pass' || nk.endsWith('_pass')) return true;
  return false;
}

function isBareN8nExpression(str) {
  if (typeof str !== 'string') return false;
  const t = str.trim();
  return t.startsWith('={{') && t.endsWith('}}');
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
    // eslint-disable-next-line no-new
    new URL(t);
    return true;
  } catch {
    return false;
  }
}

function isHighEntropyToken(str) {
  if (typeof str !== 'string') return false;
  const t = str.trim();
  if (t.length < 24 || t.length > 4096) return false;
  if (/^eyJ[\w-]+\.[\w-]+\.[\w-]+$/.test(t)) return true;
  if (/^sk-[a-zA-Z0-9]{10,}/.test(t)) return true;
  if (/^sk-ant-api/.test(t)) return true;
  if (/^xox[baprs]-/.test(t)) return true;
  if (/^github_pat_/.test(t)) return true;
  if (/^glpat-/.test(t)) return true;
  if (/^rgsk_/.test(t)) return true;
  const alnum = (t.match(/[a-zA-Z0-9]/g) || []).length;
  if (alnum / t.length < 0.72) return false;
  const unique = new Set(t).size;
  if (unique < 8 && t.length > 40) return false;
  return /^[a-zA-Z0-9+/=_-]+$/.test(t) && t.length >= 32;
}

function looksLikeBearerOrTokenHeader(str) {
  if (typeof str !== 'string') return false;
  const t = str.trim();
  return /^Bearer\s+\S+/i.test(t) || /^Token\s+\S+/i.test(t);
}

function isUsernameLikeKey(key) {
  if (!key || typeof key !== 'string') return false;
  const nk = key.toLowerCase();
  return nk === 'username' || nk === 'user' || nk === 'login' || nk.endsWith('username');
}

function shouldSkipValueScanByPath(pathStr, lastKey) {
  const pl = pathStr.toLowerCase();
  for (const k of SKIP_VALUE_SCAN_KEYS) {
    if (pl.includes(`.${k}.`) || pl.endsWith(`.${k}`) || pl.includes(`["${k}"]`)) return true;
  }
  if (lastKey && SKIP_VALUE_SCAN_KEYS.has(String(lastKey).toLowerCase())) return true;
  return false;
}

/** IDs / list keys that often hold long non-secret resource identifiers */
function isLikelyNonSecretResourcePath(pathStr, lastKeyClean) {
  const pl = pathStr.toLowerCase();
  if (lastKeyClean !== 'value') return false;
  if (
    pl.includes('.documentid.') ||
    pl.includes('.sheetname.') ||
    pl.includes('.sheetid.') ||
    pl.includes('.spreadsheetid.') ||
    pl.includes('.driveid.') ||
    pl.includes('.folderid.') ||
    pl.includes('.channelid.') ||
    pl.includes('.videoid.')
  ) {
    return true;
  }
  return false;
}

function classifyHardcodedNote({
  fieldPath,
  lastKey,
  valueStr,
  nodeType,
  isSetAssignmentValue,
}) {
  const pathL = fieldPath.toLowerCase();
  const keyL = (lastKey || '').toLowerCase();

  if (isSetAssignmentValue) return 'set node secret value';

  if (
    looksLikeBearerOrTokenHeader(valueStr) ||
    keyL === 'authorization' ||
    pathL.includes('authorization') ||
    (keyL.includes('auth') && pathL.includes('header'))
  ) {
    return 'hardcoded Authorization header';
  }

  if (pathL.includes('webhook_secret') || keyL.includes('webhook_secret')) {
    return 'hardcoded webhook secret';
  }

  if (
    keyL.includes('apikey') ||
    keyL.includes('api_key') ||
    pathL.includes('apikey') ||
    pathL.includes('x-api-key') ||
    pathL.includes('x_api_key')
  ) {
    return 'hardcoded API key';
  }

  if (nodeType === 'n8n-nodes-base.httpRequest' && pathL.includes('header') && isSecretLikeKey(lastKey)) {
    return 'hardcoded Authorization header';
  }

  return 'hardcoded password/token';
}

function serviceFromNodeType(nodeType) {
  if (!nodeType || typeof nodeType !== 'string') return 'unknown';
  const m = nodeType.match(/n8n-nodes-base\.(.+)/);
  return m ? m[1] : nodeType;
}

function buildMiscPieces({ nodeName, nodeType, workflowName, filePath, fieldPath, credId }) {
  const base = [
    `node="${nodeName}"`,
    `type="${nodeType}"`,
    `workflow="${workflowName}"`,
    `file="${path.basename(filePath)}"`,
    `path=${fieldPath}`,
  ];
  if (credId !== undefined && credId !== null && credId !== '') {
    base.push(`credId=${credId}`);
  }
  return base.join('; ');
}

function dedupKey(filePath, workflowName, nodeId, fieldPath, passwordVal, credAccount) {
  return [
    path.normalize(filePath),
    workflowName || '',
    nodeId || '',
    fieldPath || '',
    passwordVal || '',
    credAccount || '',
  ].join('\t');
}

/** Join path parts: assignments.assignments[2].value */
function pathPartsToFieldPath(parts) {
  let s = '';
  for (const p of parts) {
    if (p.startsWith('[')) s += p;
    else s += (s ? '.' : '') + p;
  }
  return s;
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

function isSetNodeAssignmentValue(pathParts) {
  if (pathParts.length < 4) return false;
  const last = pathParts[pathParts.length - 1];
  const idx = pathParts[pathParts.length - 2];
  const a1 = pathParts[pathParts.length - 3];
  const a0 = pathParts[pathParts.length - 4];
  return last === 'value' && /^\[\d+\]$/.test(idx) && a1 === 'assignments' && a0 === 'assignments';
}

function walkParametersForSecrets(
  obj,
  pathParts,
  node,
  workflowName,
  filePath,
  onFinding,
  ctx,
  parentObj,
) {
  if (obj === null || obj === undefined) return;

  const fieldTail = pathPartsToFieldPath(pathParts);
  const pathStr = fieldTail ? `parameters.${fieldTail}` : 'parameters';

  if (typeof obj === 'string') {
    const lastKey = pathParts[pathParts.length - 1] || '';
    const lastKeyClean = String(lastKey).replace(/\[\d+\]$/, '');
    const headerLabel =
      lastKeyClean === 'value' &&
      pathStr.toLowerCase().includes('header') &&
      parentObj &&
      typeof parentObj === 'object' &&
      !Array.isArray(parentObj) &&
      parentObj.name != null &&
      parentObj.type === undefined
        ? String(parentObj.name)
        : null;
    const effectiveKeyForClassify = headerLabel || lastKeyClean;
    if (shouldSkipValueScanByPath(pathStr, lastKeyClean)) return;

    if (isBareN8nExpression(obj)) return;
    const trimmed = obj.trim();
    if (!trimmed) return;

    const keyFromPath = typeof effectiveKeyForClassify === 'string' ? effectiveKeyForClassify : '';
    const secretKey = isSecretLikeKey(keyFromPath) || (headerLabel && looksLikeBearerOrTokenHeader(trimmed));
    const longPlain = trimmed.length > 900 && !secretKey;
    if (longPlain) return;

    let emit = false;
    if (secretKey) emit = true;
    else if (looksLikeBearerOrTokenHeader(trimmed)) emit = true;
    else if (isHighEntropyToken(trimmed)) emit = true;

    if (!emit) return;

    if (
      !secretKey &&
      !looksLikeBearerOrTokenHeader(trimmed) &&
      isLikelyNonSecretResourcePath(pathStr, lastKeyClean)
    ) {
      return;
    }

    const isSetAssignmentValue =
      node.type === 'n8n-nodes-base.set' && isSetNodeAssignmentValue(pathParts);

    const note = classifyHardcodedNote({
      fieldPath: pathStr,
      lastKey: keyFromPath,
      valueStr: trimmed,
      nodeType: node.type,
      isSetAssignmentValue,
    });

    const urlCol = looksLikeHttpUrl(trimmed) ? trimmed : '';
    const emailCol = looksLikeEmail(trimmed) ? trimmed : '';
    const phoneCol = looksLikePhone(trimmed) ? trimmed : '';
    const userCol =
      isUsernameLikeKey(effectiveKeyForClassify) && !looksLikeEmail(trimmed) ? trimmed : '';

    onFinding({
      Owner: OWNER,
      Service: serviceFromNodeType(node.type),
      Account: '',
      URL: urlCol,
      Username: userCol,
      Email: emailCol,
      Phone: phoneCol,
      Password: trimmed,
      Miscellaneous: buildMiscPieces({
        nodeName: node.name,
        nodeType: node.type,
        workflowName,
        filePath,
        fieldPath: headerLabel ? `${pathStr} (header name: ${headerLabel})` : pathStr,
      }),
      Notes: note,
      _dedupAccount: '',
      _fieldPath: headerLabel ? `${pathStr}:${headerLabel}` : pathStr,
    });
    return;
  }

  if (typeof obj === 'number') {
    const lastSeg = pathParts[pathParts.length - 1] || '';
    const lastKeyClean = String(lastSeg).replace(/\[\d+\]$/, '');
    if (!isSecretLikeKey(lastKeyClean)) return;
    const s = String(obj);
    if (s.length < 8) return;
    const pathStrNum = pathParts.length ? `parameters.${pathParts.join('.')}` : 'parameters';
    onFinding({
      Owner: OWNER,
      Service: serviceFromNodeType(node.type),
      Account: '',
      URL: '',
      Username: '',
      Email: '',
      Phone: '',
      Password: s,
      Miscellaneous: buildMiscPieces({
        nodeName: node.name,
        nodeType: node.type,
        workflowName,
        filePath,
        fieldPath: pathStrNum,
      }),
      Notes: 'hardcoded password/token',
      _dedupAccount: '',
      _fieldPath: pathStrNum,
    });
    return;
  }

  if (typeof obj !== 'object') return;

  if (Array.isArray(obj)) {
    obj.forEach((item, i) => {
      walkParametersForSecrets(
        item,
        [...pathParts, `[${i}]`],
        node,
        workflowName,
        filePath,
        onFinding,
        ctx,
        null,
      );
    });
    return;
  }

  for (const [k, v] of Object.entries(obj)) {
    walkParametersForSecrets(v, [...pathParts, k], node, workflowName, filePath, onFinding, ctx, obj);
  }
}

function processWorkflowFile(filePath, stats) {
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
    const nodeId = node.id || '';
    const nodeName = node.name || '';
    const nodeType = node.type || '';

    if (node.credentials && typeof node.credentials === 'object') {
      for (const [serviceKey, credObj] of Object.entries(node.credentials)) {
        if (!credObj || typeof credObj !== 'object') continue;
        const account = credObj.name != null ? String(credObj.name) : '';
        const credId = credObj.id != null ? String(credObj.id) : '';
        const fieldPath = `credentials.${serviceKey}`;
        const emailCol = looksLikeEmail(account) ? account : '';

        stats.credentialRefs++;

        stats.rows.push({
          Owner: OWNER,
          Service: serviceKey,
          Account: account,
          URL: '',
          Username: '',
          Email: emailCol,
          Phone: '',
          Password: '',
          Miscellaneous: buildMiscPieces({
            nodeName,
            nodeType,
            workflowName,
            filePath,
            fieldPath,
            credId,
          }),
          Notes: 'n8n credential reference',
          _dedupAccount: account,
          _dedupFieldPath: fieldPath,
          _dedupPassword: '',
          _dedupNodeId: nodeId,
          _sourceFile: path.normalize(filePath),
        });
      }
    }

    if (node.parameters && typeof node.parameters === 'object') {
      walkParametersForSecrets(
        node.parameters,
        [],
        { name: nodeName, type: nodeType, id: nodeId },
        workflowName,
        filePath,
        (row) => {
          stats.hardcodedSecrets++;
          const src = path.normalize(filePath);
          stats.rows.push({
            ...row,
            _dedupFieldPath: row._fieldPath || row.Miscellaneous.match(/path=([^;]+)/)?.[1] || 'parameters',
            _dedupPassword: row.Password,
            _dedupNodeId: nodeId,
            _dedupAccount: row._dedupAccount || '',
            _sourceFile: src,
          });
        },
        {},
        null,
      );
    }
  }
}

function main() {
  const rawDir = process.env.N8N_WORKFLOWS_DIR;
  const rawOut = process.env.OUTPUT_CSV || './n8n-credentials-export.csv';

  if (!rawDir || !String(rawDir).trim()) {
    console.error('Missing N8N_WORKFLOWS_DIR. Copy .env.example to .env and set N8N_WORKFLOWS_DIR.');
    process.exit(1);
  }

  const workflowsDir = path.resolve(process.cwd(), rawDir);
  const outputCsv = path.resolve(process.cwd(), rawOut);

  if (!fs.existsSync(workflowsDir)) {
    console.error(`Workflow directory does not exist: ${workflowsDir}`);
    process.exit(1);
  }

  const pattern = path.join(workflowsDir, '**/*.json').replace(/\\/g, '/');
  const files = fg.sync(pattern, { onlyFiles: true, absolute: true });

  const stats = {
    filesScanned: files.length,
    filesParsed: 0,
    filesParseFailed: 0,
    filesFailedRead: 0,
    filesNotWorkflow: 0,
    workflowsParsed: 0,
    credentialRefs: 0,
    hardcodedSecrets: 0,
    rows: [],
  };

  for (const filePath of files) {
    processWorkflowFile(filePath, stats);
  }

  const seen = new Set();
  const uniqueRows = [];
  for (const r of stats.rows) {
    const fieldPath = r._dedupFieldPath || '';
    const nodeId = r._dedupNodeId || '';
    const wfName = (r.Miscellaneous.match(/workflow="([^"]*)"/) || [])[1] || '';
    const pwd = r._dedupPassword !== undefined ? r._dedupPassword : r.Password;
    const acct = r._dedupAccount !== undefined ? r._dedupAccount : r.Account;
    const sourceFile = r._sourceFile || '';

    const key = dedupKey(sourceFile, wfName, nodeId, fieldPath, pwd || '', acct || '');

    if (seen.has(key)) continue;
    seen.add(key);
    const {
      _dedupFieldPath,
      _dedupPassword,
      _dedupNodeId,
      _dedupAccount,
      _sourceFile,
      _fieldPath,
      ...clean
    } = r;
    uniqueRows.push(clean);
  }

  const outDir = path.dirname(outputCsv);
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  const csvBody = stringify(uniqueRows, {
    header: true,
    columns: CSV_HEADERS,
    quoted_string: true,
  });

  fs.writeFileSync(outputCsv, csvBody, 'utf8');

  console.log('--- n8n credentials export summary ---');
  console.log(`Files scanned:        ${stats.filesScanned}`);
  console.log(`Workflows parsed:     ${stats.workflowsParsed}`);
  console.log(`JSON parse failures:  ${stats.filesParseFailed}`);
  console.log(`Non-workflow JSON:    ${stats.filesNotWorkflow}`);
  console.log(`Credential refs:      ${stats.credentialRefs}`);
  console.log(`Hardcoded detections: ${stats.hardcodedSecrets}`);
  console.log(`Unique CSV rows:      ${uniqueRows.length}`);
  console.log(`Output CSV:           ${outputCsv}`);
}

main();
