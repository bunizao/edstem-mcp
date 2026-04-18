import { createHmac, timingSafeEqual } from "node:crypto";

import type { OAuthConfig, OAuthUserConfig } from "../config.js";

export interface SessionPayload {
  displayName: string;
  expiresAt: number;
  userId: string;
  username: string;
}

export function buildSessionCookie(
  session: SessionPayload,
  config: OAuthConfig,
  now: Date = new Date()
): string {
  const payload = encodePayload(session, config.sessionSecret);
  const secure = config.issuerUrl.protocol === "https:";
  const maxAge = Math.max(0, Math.floor((session.expiresAt - now.getTime()) / 1000));
  const parts = [
    `${config.sessionCookieName}=${encodeURIComponent(payload)}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    `Max-Age=${maxAge}`
  ];
  if (secure) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

export function buildExpiredSessionCookie(config: OAuthConfig): string {
  const parts = [
    `${config.sessionCookieName}=`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "Max-Age=0"
  ];
  if (config.issuerUrl.protocol === "https:") {
    parts.push("Secure");
  }
  return parts.join("; ");
}

export function createSessionForUser(
  user: OAuthUserConfig,
  sessionTtlSeconds: number,
  now: Date = new Date()
): SessionPayload {
  return {
    displayName: user.displayName,
    expiresAt: now.getTime() + sessionTtlSeconds * 1000,
    userId: user.id,
    username: user.username
  };
}

export function readSessionFromCookieHeader(
  cookieHeader: string | undefined,
  config: OAuthConfig,
  now: Date = new Date()
): SessionPayload | null {
  const cookies = parseCookies(cookieHeader);
  const raw = cookies.get(config.sessionCookieName);
  if (!raw) {
    return null;
  }

  const payload = decodePayload(raw, config.sessionSecret);
  if (!payload) {
    return null;
  }
  if (payload.expiresAt <= now.getTime()) {
    return null;
  }
  return payload;
}

function parseCookies(cookieHeader: string | undefined): Map<string, string> {
  const cookies = new Map<string, string>();
  if (!cookieHeader) {
    return cookies;
  }

  for (const fragment of cookieHeader.split(";")) {
    const trimmed = fragment.trim();
    if (!trimmed) {
      continue;
    }
    const separator = trimmed.indexOf("=");
    if (separator <= 0) {
      continue;
    }
    const key = trimmed.slice(0, separator);
    const value = trimmed.slice(separator + 1);
    cookies.set(key, decodeURIComponent(value));
  }
  return cookies;
}

function encodePayload(payload: SessionPayload, secret: string): string {
  const encoded = Buffer.from(JSON.stringify(payload), "utf-8").toString("base64url");
  const signature = sign(encoded, secret);
  return `${encoded}.${signature}`;
}

function decodePayload(raw: string, secret: string): SessionPayload | null {
  const separator = raw.lastIndexOf(".");
  if (separator <= 0) {
    return null;
  }

  const encoded = raw.slice(0, separator);
  const signature = raw.slice(separator + 1);
  if (!verify(encoded, signature, secret)) {
    return null;
  }

  try {
    const json = Buffer.from(encoded, "base64url").toString("utf-8");
    const parsed = JSON.parse(json) as Partial<SessionPayload>;
    if (
      typeof parsed.displayName !== "string" ||
      typeof parsed.expiresAt !== "number" ||
      typeof parsed.userId !== "string" ||
      typeof parsed.username !== "string"
    ) {
      return null;
    }
    return {
      displayName: parsed.displayName,
      expiresAt: parsed.expiresAt,
      userId: parsed.userId,
      username: parsed.username
    };
  } catch {
    return null;
  }
}

function sign(value: string, secret: string): string {
  return createHmac("sha256", secret).update(value).digest("base64url");
}

function verify(value: string, signature: string, secret: string): boolean {
  try {
    const expected = Buffer.from(sign(value, secret), "utf-8");
    const actual = Buffer.from(signature, "utf-8");
    if (expected.length !== actual.length) {
      return false;
    }
    return timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}
