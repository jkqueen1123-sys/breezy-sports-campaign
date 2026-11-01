const crypto = require('crypto');

const WINDOW_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS_PER_IP = 300;
const buckets = globalThis.__examMessageRateBuckets || (globalThis.__examMessageRateBuckets = new Map());

function normalizeSurname(value) {
  return String(value || '').normalize('NFKC').trim().replace(/\s+/g, ' ').toLocaleLowerCase('en-US');
}

function getBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return {};
}

function send(res, status, payload) {
  res.status(status).setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  return res.end(JSON.stringify(payload));
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return send(res, 405, { ok: false, message: 'Method not allowed.' });
  }

  const secret = process.env.EXAM_LOOKUP_SECRET;
  const datasetText = process.env.EXAM_MESSAGES_JSON;
  if (!secret || !datasetText) {
    return send(res, 503, { ok: false, message: 'Your personal messages are being prepared. Please check back shortly.' });
  }

  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const ip = forwarded || 'unknown';
  const ipKey = crypto.createHmac('sha256', secret).update(ip).digest('hex');
  const now = Date.now();
  let bucket = buckets.get(ipKey);
  if (!bucket || now - bucket.startedAt > WINDOW_MS) bucket = { startedAt: now, count: 0 };
  bucket.count += 1;
  buckets.set(ipKey, bucket);
  if (buckets.size > 2000) {
    for (const [key, value] of buckets) {
      if (now - value.startedAt > WINDOW_MS) buckets.delete(key);
    }
  }
  if (bucket.count > MAX_ATTEMPTS_PER_IP) {
    return send(res, 429, { ok: false, message: 'Too many attempts from this connection. Please wait a few minutes and try again.' });
  }

  const body = getBody(req);
  const surname = normalizeSurname(body.surname);
  const cardNumber = String(body.cardNumber || '').trim();
  if (!surname || surname.length > 60 || !/^\d{4}$/.test(cardNumber)) {
    return send(res, 400, { ok: false, message: 'Enter your surname and exactly four matriculation digits.' });
  }

  let records;
  try { records = JSON.parse(datasetText); }
  catch { return send(res, 503, { ok: false, message: 'The message service is temporarily unavailable. Please try again shortly.' }); }

  const lookupKey = crypto.createHmac('sha256', secret).update(surname + '|' + cardNumber).digest('hex');
  const record = records[lookupKey];
  if (!record || typeof record.message !== 'string' || typeof record.firstName !== 'string') {
    return send(res, 404, { ok: false, message: 'We could not match those details. Check the surname spelling and last four digits, then try again.' });
  }

  return send(res, 200, { ok: true, firstName: record.firstName, message: record.message });
};
