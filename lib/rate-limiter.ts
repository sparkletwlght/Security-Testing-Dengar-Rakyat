/**
 * Rate Limiter - Iterasi 2 H4/H5 Complete
 * In-memory rate limiting with fail-closed policy
 * - Login attempts (per IP + per email)
 * - Password reset requests
 * - API endpoints
 * 
 * IMPORTANT: Fail-closed policy
 * - If rate limiter fails (e.g., store unavailable), DENY request
 * - Never fail-open on rate limit errors
 */

interface RateLimitEntry {
  count: number;
  resetAt: number;
  firstAttemptAt: number;
}

// In-memory store (production: use Redis with TTL)
const store = new Map<string, RateLimitEntry>();

type LoginBlockLevel = "temporary" | "extended";
interface LoginFailureEntry {
  failures: number;
  expiresAt: number;
  blockedUntil: number;
  blockLevel?: LoginBlockLevel;
}

const loginFailureStore = new Map<string, LoginFailureEntry>();
const LOGIN_WARNING_AFTER = 3;
const LOGIN_TEMP_BLOCK_AFTER = 5;
const LOGIN_TEMP_BLOCK_MS = 15 * 60 * 1000;
const LOGIN_EXTENDED_BLOCK_MS = 24 * 60 * 60 * 1000;
const LOGIN_FAILURE_TTL_MS = 24 * 60 * 60 * 1000;
const LOGIN_FAILURE_STORE_MAX_ENTRIES = 50_000;

export type LoginAttemptKey = { key: string; scope: "account" | "ip" };

/** Check login lock state without counting a successful credential check as a failure. */
export function getLoginBlock(keys: LoginAttemptKey[]): {
  blocked: boolean;
  retryAfter: number;
  level?: LoginBlockLevel;
} {
  const now = Date.now();
  for (const [key, entry] of loginFailureStore) {
    if (entry.expiresAt <= now) loginFailureStore.delete(key);
  }

  if (loginFailureStore.size >= LOGIN_FAILURE_STORE_MAX_ENTRIES && keys.some(({ key }) => !loginFailureStore.has(key))) {
    throw new Error("Login failure store capacity reached");
  }

  // Account lock takes precedence so a repeated attempt after the 15-minute
  // cooldown can escalate to a 24-hour lock for that account only.
  for (const { key, scope } of keys) {
    const entry = loginFailureStore.get(key);
    if (!entry || entry.blockedUntil <= now) continue;

    if (scope === "account" && entry.blockLevel === "temporary") {
      entry.blockLevel = "extended";
      entry.blockedUntil = now + LOGIN_EXTENDED_BLOCK_MS;
      entry.expiresAt = entry.blockedUntil;
    }

    return {
      blocked: true,
      retryAfter: Math.max(1, Math.ceil((entry.blockedUntil - now) / 1000)),
      level: entry.blockLevel,
    };
  }
  return { blocked: false, retryAfter: 0 };
}

/** Record an invalid credential and return warning/lockout details. */
export function recordFailedLogin(keys: LoginAttemptKey[]): {
  failures: number;
  warning?: string;
  attemptsRemaining: number;
  blocked: boolean;
  retryAfter?: number;
  level?: LoginBlockLevel;
} {
  const now = Date.now();
  // Bound unauthenticated per-email keys so random email submissions cannot
  // grow this process-local map without limit. Remove expired entries first.
  for (const [key, entry] of loginFailureStore) {
    if (entry.expiresAt <= now) loginFailureStore.delete(key);
  }
  const updated: Array<{ key: string; scope: LoginAttemptKey["scope"]; entry: LoginFailureEntry }> = [];

  for (const { key, scope } of keys) {
    let entry = loginFailureStore.get(key);
    if (!entry || entry.expiresAt <= now) {
      if (loginFailureStore.size >= LOGIN_FAILURE_STORE_MAX_ENTRIES) {
        throw new Error("Login failure store capacity reached");
      }
      entry = { failures: 0, expiresAt: now + LOGIN_FAILURE_TTL_MS, blockedUntil: 0 };
    }
    entry.failures += 1;
    entry.expiresAt = now + LOGIN_FAILURE_TTL_MS;
    if (entry.failures >= LOGIN_TEMP_BLOCK_AFTER) {
      entry.blockLevel = "temporary";
      entry.blockedUntil = now + LOGIN_TEMP_BLOCK_MS;
    }
    if (scope === "account" && entry.failures >= LOGIN_TEMP_BLOCK_AFTER + 1) {
      entry.blockLevel = "extended";
      entry.blockedUntil = now + LOGIN_EXTENDED_BLOCK_MS;
      entry.expiresAt = entry.blockedUntil;
    }
    loginFailureStore.set(key, entry);
    updated.push({ key, scope, entry });
  }

  const accountEntry = updated.find(({ scope }) => scope === "account")?.entry;
  const maxFailures = Math.max(...updated.map(({ entry }) => entry.failures));
  const blockedEntry = updated.find(({ entry }) => entry.blockedUntil > now)?.entry;
  const warning = accountEntry && accountEntry.failures >= LOGIN_WARNING_AFTER && accountEntry.failures < LOGIN_TEMP_BLOCK_AFTER
    ? `Peringatan: ${LOGIN_TEMP_BLOCK_AFTER - accountEntry.failures} percobaan gagal lagi akan memblokir login selama 15 menit.`
    : undefined;

  return {
    failures: accountEntry?.failures ?? maxFailures,
    warning,
    attemptsRemaining: Math.max(0, LOGIN_TEMP_BLOCK_AFTER - (accountEntry?.failures ?? maxFailures)),
    blocked: Boolean(blockedEntry),
    retryAfter: blockedEntry ? Math.max(1, Math.ceil((blockedEntry.blockedUntil - now) / 1000)) : undefined,
    level: blockedEntry?.blockLevel,
  };
}

export function resetLoginFailures(keys: LoginAttemptKey[]): void {
  for (const { key } of keys) loginFailureStore.delete(key);
}

// Cleanup old entries every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of store.entries()) {
    if (entry.resetAt < now) {
      store.delete(key);
    }
  }
  for (const [key, entry] of loginFailureStore.entries()) {
    if (entry.expiresAt <= now) loginFailureStore.delete(key);
  }
}, 10 * 60 * 1000);

/**
 * Check if request is rate limited (FAIL-CLOSED)
 * @param key Identifier (email, IP, etc)
 * @param maxAttempts Max attempts allowed
 * @param windowMs Time window in milliseconds
 * @returns { allowed: boolean, remaining: number, resetAt: number }
 * 
 * @throws Error if rate limiter fails (fail-closed policy)
 */
export function checkRateLimit(
  key: string,
  maxAttempts: number,
  windowMs: number
): {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
} {
  try {
    const now = Date.now();
    if (store.size >= 50_000 && !store.has(key)) {
      for (const [storedKey, storedEntry] of store.entries()) {
        if (storedEntry.resetAt < now) store.delete(storedKey);
      }
      if (store.size >= 50_000) throw new Error("Rate limiter capacity reached");
    }
    const entry = store.get(key);

    // No entry or window expired
    if (!entry || entry.resetAt < now) {
      const resetAt = now + windowMs;
      store.set(key, { count: 1, resetAt, firstAttemptAt: now });
      return {
        allowed: true,
        remaining: maxAttempts - 1,
        resetAt,
      };
    }

    // Within window
    entry.count++;
    store.set(key, entry);

    const allowed = entry.count <= maxAttempts;
    const remaining = Math.max(0, maxAttempts - entry.count);
    const retryAfter = allowed ? undefined : Math.ceil((entry.resetAt - now) / 1000);

    return {
      allowed,
      remaining,
      resetAt: entry.resetAt,
      retryAfter,
    };
  } catch (error) {
    // FAIL-CLOSED: If rate limiter fails, deny request
    console.error("[RATE_LIMIT] Error checking rate limit:", error);
    throw new Error("Rate limiter unavailable");
  }
}

/**
 * Check multiple rate limits (composite check)
 * E.g., check both IP and email rate limits for login
 * 
 * ALL checks must pass (fail-closed)
 */
export function checkMultipleRateLimits(
  checks: Array<{ key: string; maxAttempts: number; windowMs: number }>
): {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
  failedCheck?: string;
} {
  const results = checks.map((check) => ({ check, result: checkRateLimit(check.key, check.maxAttempts, check.windowMs) }));
  const minRemaining = Math.min(...results.map(({ result }) => result.remaining));
  const maxResetAt = Math.max(...results.map(r => r.result.resetAt));
  const failed = results.find(({ result }) => !result.allowed);
  if (failed) return { ...failed.result, failedCheck: failed.check.key };

  return {
    allowed: true,
    remaining: minRemaining,
    resetAt: maxResetAt,
  };
}

/**
 * Reset rate limit for a key (e.g., after successful login)
 */
export function resetRateLimit(key: string): void {
  store.delete(key);
}

/**
 * Get remaining attempts
 */
export function getRemainingAttempts(
  key: string,
  maxAttempts: number
): number {
  const entry = store.get(key);
  if (!entry || entry.resetAt < Date.now()) {
    return maxAttempts;
  }
  return Math.max(0, maxAttempts - entry.count);
}

/**
 * Rate limit presets (spec: 5 login failures then wait)
 */
export const RateLimits = {
  PASSWORD_RESET: { maxAttempts: 3, windowMs: 60 * 60 * 1000 }, // 3 per hour
  API_GENERAL: { maxAttempts: 100, windowMs: 60 * 1000 }, // 100 per minute
  REGISTER: { maxAttempts: 3, windowMs: 60 * 60 * 1000 }, // 3 per hour
  
  // Laporan spam prevention (spec: max 10 reports per day)
  LAPORAN_CREATE: { maxAttempts: 10, windowMs: 24 * 60 * 60 * 1000 },
};
