/**
 * Request Context Utilities - Iterasi 3 P1 Enhanced
 * Extract IP address, user agent untuk audit logging
 * WITH trusted proxy validation (prevent IP spoofing)
 */

import type { NextRequest } from "next/server";
import { isIP } from "node:net";
import type { AuditRequestContext } from "@/features/audit/audit.types";

/**
 * Trusted proxies (load balancers, reverse proxies)
 * Only trust X-Forwarded-For from these IPs
 * 
 * Production: Add your actual proxy IPs here
 * Format: ["10.0.0.1", "192.168.1.1", "172.16.0.0/12"]
 */
const TRUSTED_PROXIES = process.env.TRUSTED_PROXIES?.split(",").map(ip => ip.trim()) || [
  "127.0.0.1",        // Localhost
  "::1",              // IPv6 localhost
  // Add your actual proxy IPs in production
];

/**
 * Check if IP is in trusted proxy list
 * TODO: Support CIDR notation for IP ranges
 */
function isTrustedProxy(ip: string): boolean {
  return TRUSTED_PROXIES.includes(ip);
}

/**
 * Extract IP address from request (with trusted proxy validation)
 * Prevents IP spoofing attacks
 * 
 * @param request Request object
 * @param directIP Direct connection IP (from socket, if available)
 * @returns Client IP address
 */
export function getClientIP(
  request: Request | NextRequest,
  directIP?: string
): string | undefined {
  if (directIP) {
    if (!isIP(directIP)) return "unknown";
    if (!isTrustedProxy(directIP)) return directIP;
  } else if (process.env.TRUST_PROXY_HEADERS !== "true") {
    // Request headers are client controlled unless the ingress proxy is
    // configured to overwrite them. Never trust CF/X-Forwarded-For implicitly.
    return "unknown";
  }

  // Only use forwarding headers when deployment explicitly guarantees that
  // the reverse proxy strips incoming values and writes its own.
  const candidate = request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-real-ip") ||
    request.headers.get("x-forwarded-for")?.split(",")[0].trim();
  return candidate && isIP(candidate) ? candidate : directIP || "unknown";
}

/**
 * Extract user agent from request
 */
export function getUserAgent(request: Request | NextRequest): string | undefined {
  return request.headers.get("user-agent") || undefined;
}

/**
 * Extract request context for audit logging
 * 
 * @param request Request object
 * @param directIP Direct connection IP (optional, for trusted proxy validation)
 */
export function getRequestContext(
  request: Request | NextRequest,
  directIP?: string
) {
  const requestUrl = new URL(request.url);
  const service: "HTTP" | "HTTPS" = requestUrl.protocol === "https:" ? "HTTPS" : "HTTP";
  return {
    ip_address: getClientIP(request, directIP),
    user_agent: getUserAgent(request),
    service,
    request_method: request.method,
    // Keep query parameters out of access logs; they may contain sensitive data.
    request_path: requestUrl.pathname,
  };
}

/** Request details safe to persist in the audit metadata (query string omitted). */
export function getAuditRequestContext(
  request: Request | NextRequest,
  httpStatus: number
): AuditRequestContext {
  const url = new URL(request.url);
  return {
    method: request.method,
    path: url.pathname,
    service: url.protocol === "https:" ? "HTTPS" : "HTTP",
    http_status: httpStatus,
  };
}
