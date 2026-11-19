// اختبار ذاتي للتشفير (بدون بوت): يتأكد أن seal/open متوافقان ويفشلان عند التلاعب.
import crypto from 'node:crypto'
process.env.LUNA_API_KEY ||= crypto.randomBytes(32).toString('hex')
const { sealCookie, openCookie } = await import('../lib/secure.js')
const c = sealCookie('abc'.repeat(10))
console.log('cookie roundtrip:', openCookie(c) === 'abc'.repeat(10))
console.log('tampered cookie rejected:', openCookie(c.slice(0, -2) + 'AA') === '')
