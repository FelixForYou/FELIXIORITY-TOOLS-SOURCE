import Redis from "ioredis";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { AppError } from "./errors";
import { hash, token } from "./security";
import type { Session, Audit } from "./model";
const g = globalThis as unknown as { felixRedis?: Redis };
export function redis() {
  if (!process.env.REDIS_URL)
    throw new AppError(503, "CONFIG", "REDIS_URL belum dikonfigurasi.");
  return (g.felixRedis ??= new Redis(process.env.REDIS_URL, {
    maxRetriesPerRequest: 1,
    connectTimeout: 3000,
    lazyConnect: true,
    enableOfflineQueue: false,
  }));
}
export async function db() {
  const r = redis();
  if (r.status === "wait") await r.connect();
  if (r.status === "connecting")
    await new Promise<void>((res, rej) => {
      r.once("ready", res);
      r.once("error", rej);
    });
  return r;
}
function encryptionKey() {
  const s = process.env.SESSION_SECRET;
  if (!s || !/^[a-f0-9]{64}$/i.test(s))
    throw new AppError(
      503,
      "CONFIG",
      "SESSION_SECRET harus 64 karakter hex acak.",
    );
  return Buffer.from(s, "hex");
}
export function seal(value: unknown) {
  const iv = randomBytes(12),
    c = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const data = Buffer.concat([c.update(JSON.stringify(value)), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), data]).toString("base64");
}
export function unseal<T>(v: string): T {
  const b = Buffer.from(v, "base64"),
    d = createDecipheriv("aes-256-gcm", encryptionKey(), b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return JSON.parse(
    Buffer.concat([d.update(b.subarray(28)), d.final()]).toString(),
  );
}
export async function get<T>(key: string) {
  const v = await (await db()).get("felix:" + key);
  return v ? (JSON.parse(v) as T) : null;
}
export async function put(key: string, v: unknown, ttl = 3600) {
  await (await db()).set("felix:" + key, JSON.stringify(v), "EX", ttl);
}
export async function del(key: string) {
  await (await db()).del("felix:" + key);
}
export async function saveSession(sid: string, s: Session) {
  await (
    await db()
  ).set(
    "felix:session:" + hash(sid),
    seal(s),
    "EX",
    Math.max(1, Math.ceil((s.expiresAt - Date.now()) / 1000)),
  );
}
export async function session(sid: string) {
  if (!/^[a-f0-9]{64}$/.test(sid))
    throw new AppError(
      401,
      "SESSION_EXPIRED",
      "Sesi berakhir. Hubungkan panel kembali.",
    );
  const v = await (await db()).get("felix:session:" + hash(sid));
  if (!v)
    throw new AppError(
      401,
      "SESSION_EXPIRED",
      "Sesi berakhir. Hubungkan panel kembali.",
    );
  const s = unseal<Session>(v);
  if (s.expiresAt < Date.now())
    throw new AppError(401, "SESSION_EXPIRED", "Sesi berakhir.");
  return s;
}
export async function rate(key: string, limit: number, seconds = 60) {
  const r = await db(),
    k = "felix:rate:" + hash(key);
  const n = Number(
    await r.eval(
      "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return n",
      1,
      k,
      seconds,
    ),
  );
  if (n > limit)
    throw new AppError(
      429,
      "RATE_LIMIT",
      "Terlalu banyak permintaan. Tunggu sebentar.",
      seconds,
    );
}
export const panelKey = (s: Session) => hash(s.domain);
export const scope = (sid: string) => hash(sid);
export async function audit(
  s: Session,
  action: string,
  outcome: string,
  target?: number,
) {
  const r = await db(),
    k = "felix:audit:" + panelKey(s);
  const item: Audit = { at: new Date().toISOString(), action, outcome, target };
  await r.lpush(k, JSON.stringify(item));
  await r.ltrim(k, 0, 999);
  await r.expire(k, 2592000);
}
export async function logs(s: Session) {
  return (await (await db()).lrange("felix:audit:" + panelKey(s), 0, 999)).map(
    (v) => JSON.parse(v) as Audit,
  );
}
export async function protectedIds(s: Session) {
  return (await (await db()).smembers("felix:protected:" + panelKey(s))).map(
    Number,
  );
}
export async function protect(s: Session, id: number, on: boolean) {
  const r = await db(),
    k = "felix:protected:" + panelKey(s);
  if (on) await r.sadd(k, id);
  else await r.srem(k, id);
}
export async function locked<T>(
  key: string,
  fn: (assertHeld: () => Promise<void>) => Promise<T>,
) {
  const r = await db(),
    k = "felix:lock:" + key,
    t = token();
  if (!(await r.set(k, t, "PX", 120000, "NX")))
    throw new AppError(409, "BUSY", "Operasi lain sedang berjalan. Coba lagi.");
  let lost = false;
  const renew = setInterval(() => {
    void r
      .eval(
        "if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('PEXPIRE',KEYS[1],120000) else return 0 end",
        1,
        k,
        t,
      )
      .then((value) => {
        if (Number(value) !== 1) lost = true;
      })
      .catch(() => {
        lost = true;
      });
  }, 20000);
  renew.unref();
  const assertHeld = async () => {
    if (lost || (await r.get(k)) !== t)
      throw new AppError(
        409,
        "LOCK_LOST",
        "Kunci operasi terputus. Tidak melanjutkan mutasi.",
      );
  };
  try {
    return await fn(assertHeld);
  } finally {
    clearInterval(renew);
    await r.eval(
      "if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end",
      1,
      k,
      t,
    );
  }
}
