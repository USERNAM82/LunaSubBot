// lib/secure.js — نفس بروتوكول التشفير الموجود في البوت (web/panel/apikey.js). لا يُرسل المفتاح أبدًا؛ يُستعمل لاشتقاق مفاتيح AES-256-GCM.
import crypto from 'node:crypto'

const b64u = (buf) => Buffer.from(buf).toString('base64url')
let cache = null

// القيم المدمجة تعمل مباشرة بدون إعداد. تُتجاوز بمتغيرات البيئة LUNA_API_KEY / LUNA_BOT_URL في Vercel إن أردت.
const BUILTIN_KEY = 'd9f0fcb8d9000b3ff8b8c851497022b5c5f72b05046d23826e63b8ee18ae62ef'
export const DEFAULT_BOT_URL = 'https://lunabot.hidenplay.net'
export const getBotUrl = () => String(process.env.LUNA_BOT_URL || '').trim() || DEFAULT_BOT_URL

export function getKey() {
  const k = String(process.env.LUNA_API_KEY || '').trim() || BUILTIN_KEY
  if (k.length < 32) throw new Error('API key too short (min 32 chars)')
  return k
}

function keys() {
  if (cache && cache.k === getKey()) return cache
  const ikm = Buffer.from(getKey(), 'utf8')
  const hk = (info) => Buffer.from(crypto.hkdfSync('sha256', ikm, Buffer.from('luna-sub-api/v1'), Buffer.from(info), 32))
  cache = { k: getKey(), req: hk('request'), res: hk('response'), cookie: hk('cookie') }
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
// يرمي خطأ له .code: timeout | network | redirect | auth | protocol  (للتشخيص فقط)
const err = (code, msg) => Object.assign(new Error(msg || code), { code })
export async function callBot({ botUrl, path, method, body, session, ip, query, timeoutMs = 55_000 }) {
  const ts = String(Date.now())
  const nonce = crypto.randomBytes(16).toString('hex')
  const payload = JSON.stringify({ m: method, b: body ?? '', s: session || '', ip: ip || '', q: query || '' })
  const e = seal(keys().req, payload, `${path}\n${ts}\n${nonce}`)
  let r
  try {
    r = await fetch(botUrl.replace(/\/+$/, '') + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ t: ts, n: nonce, e }),     // الوقت والnonce داخل الجسم: لا ترويسات مخصصة قد تحذفها وسطاء الاستضافة
      signal: AbortSignal.timeout(timeoutMs),
      redirect: 'manual'
    })
  } catch (x) {
    throw err(x?.name === 'TimeoutError' || x?.name === 'AbortError' ? 'timeout' : 'network', x?.cause?.code || x?.message)
  }
  if (r.status >= 300 && r.status < 400) throw err('redirect', `upstream redirected (${r.status}) to ${r.headers.get('location') || '?'}`)
  const text = await r.text()
  let env
  try { env = JSON.parse(text) } catch { throw err('protocol', `non-JSON upstream response (HTTP ${r.status})`) }
  if (!env || typeof env.e !== 'string') throw err(r.status === 401 ? 'auth' : 'protocol', `upstream HTTP ${r.status}`)
  let inner
  try { inner = JSON.parse(open(keys().res, env.e, `res\n${nonce}`)) } catch { throw err('auth', 'cannot decrypt upstream response') }
  return { status: Number(inner.s) || 502, body: String(inner.b ?? '') }
}

// ---- تشفير كوكي الجلسة (حتى لا يحمل المتصفح توكن البوت الخام) ----
export const sealCookie = (token) => seal(keys().cookie, token, 'luna_sid')
export function openCookie(v) {
  try { return open(keys().cookie, v, 'luna_sid') } catch { return '' }
}
