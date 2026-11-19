// lib/secure.js — نفس بروتوكول التشفير الموجود في البوت (web/panel/apikey.js). لا يُرسل المفتاح أبدًا؛ يُستعمل لاشتقاق مفاتيح AES-256-GCM.
import crypto from 'node:crypto'

const b64u = (buf) => Buffer.from(buf).toString('base64url')
let cache = null

export function getKey() {
  const k = String(process.env.LUNA_API_KEY || '').trim()
  if (k.length < 32) throw new Error('LUNA_API_KEY missing or too short (min 32 chars)')
  return k
}

function keys() {
  if (cache && cache.k === process.env.LUNA_API_KEY) return cache
  const ikm = Buffer.from(getKey(), 'utf8')
  const hk = (info) => Buffer.from(crypto.hkdfSync('sha256', ikm, Buffer.from('luna-sub-api/v1'), Buffer.from(info), 32))
  cache = { k: process.env.LUNA_API_KEY, req: hk('request'), res: hk('response'), cookie: hk('cookie') }
  return cache
}

function seal(key, plain, aad) {
  const iv = crypto.randomBytes(12)
  const c = crypto.createCipheriv('aes-256-gcm', key, iv)
  c.setAAD(Buffer.from(aad))
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()])
  return b64u(Buffer.concat([iv, c.getAuthTag(), ct]))
}

function open(key, token, aad) {
  const raw = Buffer.from(String(token), 'base64url')
  if (raw.length < 29) throw new Error('short')
  const d = crypto.createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12))
  d.setAAD(Buffer.from(aad))
  d.setAuthTag(raw.subarray(12, 28))
  return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8')
}

// ---- الاتصال بالبوت ----
export async function callBot({ botUrl, path, method, body, session, ip, query, timeoutMs = 55_000 }) {
  const ts = String(Date.now())
  const nonce = crypto.randomBytes(16).toString('hex')
  const payload = JSON.stringify({ m: method, b: body ?? '', s: session || '', ip: ip || '', q: query || '' })
  const e = seal(keys().req, payload, `${path}\n${ts}\n${nonce}`)
  const r = await fetch(botUrl.replace(/\/+$/, '') + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Luna-Ts': ts, 'X-Luna-Nonce': nonce },
    body: JSON.stringify({ e }),
    signal: AbortSignal.timeout(timeoutMs),
    redirect: 'error'
  })
  const text = await r.text()
  let env
  try { env = JSON.parse(text) } catch { throw new Error('bad_upstream') }
  if (!env || typeof env.e !== 'string') throw new Error(r.status === 401 ? 'upstream_unauthorized' : 'bad_upstream')
  const inner = JSON.parse(open(keys().res, env.e, `res\n${nonce}`))
  return { status: Number(inner.s) || 502, body: String(inner.b ?? '') }
}

// ---- تشفير كوكي الجلسة (حتى لا يحمل المتصفح توكن البوت الخام) ----
export const sealCookie = (token) => seal(keys().cookie, token, 'luna_sid')
export function openCookie(v) {
  try { return open(keys().cookie, v, 'luna_sid') } catch { return '' }
}
