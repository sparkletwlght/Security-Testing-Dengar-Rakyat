/**
 * Audit Service - Iterasi 3 P1 Complete
 * Tamper-proof audit logging dengan hash chain
 * WITH transaction and row-level locking (race condition prevention)
 */

import { pool } from "@/lib/db";
import { getAuditRequestContext, getRequestContext } from "@/lib/request-context";
import { hostname } from "node:os";
import {
  insertAuditLog,
  queryAuditLogs,
  verifyHashChain,
} from "./audit.queries";
import type { AuditLogEntry, AuditQuery, AuditLogRecord, AuditRequestContext } from "./audit.types";
import { generateAuditHash } from "./audit-hash";

function writeAuditAccessLine(entry: AuditLogEntry, logId: number): void {
  const safeField = (value: string) => value.replace(/[\\"\r\n]/g, " ").trim();
  const metadata = entry.metadata ?? {};
  const request = metadata.request_context as Partial<AuditRequestContext> | undefined;
  const sourceIp = safeField(entry.ip_address || "-");
  const actor = safeField(entry.user_email || (entry.user_id ? `user:${entry.user_id}` : "anonymous"));
  const userAgent = safeField(entry.user_agent || "-");
  const method = safeField(request?.method || "-");
  const path = safeField(request?.path || "-");
  const httpStatus = request?.http_status ?? (entry.status === "success" ? 200 : 0);
  const level = entry.status === "success" ? "INFO" : "WARNING";
  const category = entry.event_category === "auth"
    ? "authentication"
    : entry.event_category === "data" ? "data_activity" : "security_event";
  const eventName = entry.event_type === "login_success" || entry.event_type === "login_failure"
    ? "authentication"
    : entry.event_type === "logout" ? "session_management" : category;
  const reason = typeof metadata.reason === "string" ? metadata.reason : "-";
  const targetHostname = process.env.AUDIT_HOSTNAME || hostname();
  const destinationIp = process.env.AUDIT_DESTINATION_IP || "-";
  const service = request?.service || "unknown";

  console.info(
    `${sourceIp} - ${actor} [${new Date().toISOString()}] ` +
    `"${method} ${path} HTTP/1.1" ${httpStatus} - "-" "${userAgent}" ` +
    `level=${level} event=${eventName} action="${safeField(entry.action)}" ` +
    `status=${entry.status === "success" ? "success" : "failed"} reason=${safeField(reason)} ` +
    `role=${safeField(entry.user_role || "-")} ` +
    `target_type=${safeField(entry.target_type || "-")} target_id=${safeField(entry.target_id || "-")} ` +
    `host=${safeField(targetHostname)} dst_ip=${safeField(destinationIp)} service=${service} log_id=${logId}`
  );
}

/**
 * Log audit event (main function)
 * WITH transaction and row-level locking to prevent race conditions
 * 
 * @param entry Audit log entry
 * @returns Log ID
 */
export async function logAudit(entry: AuditLogEntry): Promise<number> {
  const connection = await pool.getConnection();
  let lockHeld = false;
  try {
    const [lockRows] = await connection.query("SELECT GET_LOCK(?, 5) AS acquired", ["dengar-rakyat-audit-chain"]);
    const lockResult = lockRows as Array<{ acquired: number | null }>;
    if (lockResult[0]?.acquired !== 1) throw new Error("Could not acquire audit-chain lock");
    lockHeld = true;
    await connection.beginTransaction();

    const [lastRows] = await connection.query("SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1 FOR UPDATE");
    const lastLog = (lastRows as Array<{ current_hash: string | null }>)[0];
    const previousHash = lastLog?.current_hash ?? null;
    const currentHash = generateAuditHash(entry, previousHash);
    const logId = await insertAuditLog(
      { ...entry, previous_hash: previousHash, current_hash: currentHash },
      async (sql, params) => {
        const [result] = await connection.execute(sql, params as (string | number | Buffer | Date | null)[]);
        return result as { insertId?: number };
      }
    );

    await connection.commit();
    try {
      writeAuditAccessLine(entry, logId);
    } catch (logError) {
      console.error("[AUDIT] Could not write terminal event:", logError);
    }
    return logId;
  } catch (error) {
    await connection.rollback().catch(() => undefined);
    // CRITICAL: Audit logging failure
    console.error("[AUDIT] Failed to log event:", error);
    // Don't throw - we don't want audit failure to break app
    // But log to stderr for monitoring
    return -1;
  } finally {
    if (lockHeld) {
      await connection.query("SELECT RELEASE_LOCK(?)", ["dengar-rakyat-audit-chain"]).catch(() => undefined);
    }
    connection.release();
  }
}

/**
 * Query audit logs
 */
export async function getAuditLogs(
  query: AuditQuery
): Promise<AuditLogRecord[]> {
  return queryAuditLogs(query);
}

/**
 * Verify hash chain integrity
 * Returns array of broken links (should be empty)
 */
export async function verifyAuditIntegrity(): Promise<{
  valid: boolean;
  brokenLinks: Array<{ id: number; expected: string; actual: string }>;
  legacyCount: number;
}> {
  const result = await verifyHashChain();
  return {
    valid: result.brokenLinks.length === 0 && result.legacyCount === 0,
    brokenLinks: result.brokenLinks,
    legacyCount: result.legacyCount,
  };
}

/**
 * Helper: Log auth events
 */
export async function logAuthEvent(params: {
  event_type: Extract<
    AuditLogEntry["event_type"],
    | "login_success"
    | "login_failure"
    | "logout"
    | "register"
    | "password_reset_request"
    | "password_reset_complete"
    | "password_change"
  >;
  user_id?: number;
  user_email?: string;
  user_role?: string;
  ip_address?: string;
  user_agent?: string;
  service?: "HTTP" | "HTTPS";
  request_method?: string;
  request_path?: string;
  http_status?: number;
  status: "success" | "failure";
  error_message?: string;
  metadata?: Record<string, any>;
}): Promise<number> {
  const actionMap = {
    login_success: "User logged in successfully",
    login_failure: "Failed login attempt",
    logout: "User logged out",
    register: "New user registered",
    password_reset_request: "Password reset requested",
    password_reset_complete: "Password reset completed",
    password_change: "Password changed",
  };

  const logId = await logAudit({
    event_type: params.event_type,
    event_category: "auth",
    action: actionMap[params.event_type],
    user_id: params.user_id,
    user_email: params.user_email,
    user_role: params.user_role,
    ip_address: params.ip_address,
    user_agent: params.user_agent,
    status: params.status,
    error_message: params.error_message,
    metadata: {
      ...params.metadata,
      request_context: {
        method: params.request_method || "-",
        path: params.request_path || "-",
        service: params.service || "HTTP",
        http_status: params.http_status ?? (params.status === "success" ? 200 : 401),
      },
    },
  });
  return logId;
}

/**
 * Helper: Log data events
 */
export async function logDataEvent(params: {
  event_type: Extract<
    AuditLogEntry["event_type"],
    | "laporan_create"
    | "laporan_read"
    | "laporan_update"
    | "laporan_delete"
    | "status_update"
    | "data_export"
    | "profile_update"
    | "comment_create"
    | "audit_read"
  >;
  user_id: number;
  user_email: string;
  user_role: string;
  request?: Request;
  http_status?: number;
  target_type: string;
  target_id: string;
  ip_address?: string;
  user_agent?: string;
  request_context?: AuditRequestContext;
  metadata?: Record<string, any>;
}): Promise<number> {
  const actionMap = {
    laporan_create: "Created new laporan",
    laporan_read: "Viewed laporan",
    laporan_update: "Updated laporan",
    laporan_delete: "Deleted laporan",
    status_update: "Changed laporan status",
    data_export: "Exported user data",
    profile_update: "Updated user profile",
    comment_create: "Created report comment",
    audit_read: "Viewed security audit trail",
  };
  const requestDetails = params.request ? getRequestContext(params.request) : undefined;
  const requestAudit = params.request_context ?? (params.request
    ? getAuditRequestContext(params.request, params.http_status ?? 200)
    : undefined);

  return logAudit({
    event_type: params.event_type,
    event_category: "data",
    action: actionMap[params.event_type],
    user_id: params.user_id,
    user_email: params.user_email,
    user_role: params.user_role,
    user_agent: params.user_agent ?? requestDetails?.user_agent,
    target_type: params.target_type,
    target_id: params.target_id,
    ip_address: params.ip_address ?? requestDetails?.ip_address,
    status: "success",
    metadata: {
      ...params.metadata,
      ...(requestAudit ? { request_context: requestAudit } : {}),
    },
  });
}

/**
 * Helper: Log system events
 */
export async function logSystemEvent(params: {
  event_type: Extract<
    AuditLogEntry["event_type"],
    "rate_limit_exceeded" | "csrf_violation" | "invalid_token" | "permission_denied" | "validation_failure"
  >;
  user_id?: number;
  user_email?: string;
  user_role?: string;
  ip_address?: string;
  user_agent?: string;
  request?: Request;
  http_status?: number;
  request_context?: AuditRequestContext;
  metadata?: Record<string, any>;
}): Promise<number> {
  const actionMap = {
    rate_limit_exceeded: "Rate limit exceeded",
    csrf_violation: "CSRF token validation failed",
    invalid_token: "Invalid or expired token",
    permission_denied: "Access denied - insufficient permissions",
    validation_failure: "Request validation failed",
  };
  const requestDetails = params.request ? getRequestContext(params.request) : undefined;
  const requestAudit = params.request_context ?? (params.request
    ? getAuditRequestContext(params.request, params.http_status ?? 403)
    : undefined);

  return logAudit({
    event_type: params.event_type,
    event_category: "system",
    action: actionMap[params.event_type],
    user_id: params.user_id,
    user_email: params.user_email,
    user_role: params.user_role,
    ip_address: params.ip_address ?? requestDetails?.ip_address,
    user_agent: params.user_agent ?? requestDetails?.user_agent,
    status: "failure",
    metadata: {
      ...params.metadata,
      ...(requestAudit ? { request_context: requestAudit } : {}),
    },
  });
}
