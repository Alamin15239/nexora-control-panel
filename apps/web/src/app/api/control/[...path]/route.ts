import { NextRequest, NextResponse } from "next/server";
import { getCloudflareContext } from "@opennextjs/cloudflare";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const DEFAULT_API_BASE = "https://api.nexoraedge.digital";
type ApiServiceBinding = { fetch(request: Request): Promise<Response> };

const COOKIE_NAME = "nexora_session";

function allowedRoute(parts: string[], method: "GET" | "POST" | "PATCH" | "DELETE" | "PUT"): boolean {
  if (parts.length === 2 && parts[0] === "customer" && parts[1] === "hosting-accounts") return method === "GET";
  if (parts.length === 3 && parts[0] === "hosting-accounts" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "memberships") return method === "GET" || method === "POST";
  if (parts.length === 4 && parts[0] === "hosting-accounts" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "memberships" && /^[0-9a-f-]{36}$/i.test(parts[3])) return method === "DELETE";
  if (parts.length === 2 && parts[0] === "platform" && parts[1] === "customers") return method === "GET";
  if (parts.length === 1 && parts[0] === "users") return method === "GET";
  if (parts.length === 2 && parts[0] === "users" && /^[0-9a-f-]{36}$/i.test(parts[1])) return method === "DELETE";
  if (parts.length === 4 && parts[0] === "customer" && parts[1] === "hosting-accounts" && /^[0-9a-f-]{36}$/i.test(parts[2]) && parts[3] === "overview") return method === "GET";
  if (parts.length === 4 && parts[0] === "customer" && parts[1] === "hosting-accounts" && /^[0-9a-f-]{36}$/i.test(parts[2]) && ["domains", "databases"].includes(parts[3])) return method === "GET";
  if (parts.length === 1 && ["servers", "hosting-plans", "hosting-accounts", "domains", "databases"].includes(parts[0])) return true;
  if (parts.length === 1 && parts[0] === "store") return method === "GET";
  if (parts.length === 2 && parts[0] === "store" && ["plans","payment-instructions","orders"].includes(parts[1])) return method === "GET" || (parts[1] === "orders" && method === "POST");
  if (parts.length === 4 && parts[0] === "store" && parts[1] === "orders" && /^[0-9a-f-]{36}$/i.test(parts[2]) && parts[3] === "receipt") return method === "POST";
  if (parts.length === 2 && parts[0] === "platform" && parts[1] === "payment-settings") return method === "GET" || method === "PUT";
  if (parts.length === 2 && parts[0] === "platform" && parts[1] === "payment-orders") return method === "GET";
  if (parts.length === 4 && parts[0] === "platform" && parts[1] === "payment-orders" && /^[0-9a-f-]{36}$/i.test(parts[2]) && parts[3] === "review") return method === "POST";
  if (parts.length === 4 && parts[0] === "platform" && parts[1] === "payment-orders" && /^[0-9a-f-]{36}$/i.test(parts[2]) && parts[3] === "receipt") return method === "GET";
  if (parts.length === 3 && parts[0] === "hosting-plans" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "store-settings") return method === "POST";
  if (parts.length === 2 && parts[0] === "hosting-plans" && /^[0-9a-f-]{36}$/i.test(parts[1])) return method === "PUT";
  if (parts.length === 3 && parts[0] === "hosting-accounts" && /^[0-9a-f-]{36}$/i.test(parts[1]) && (parts[2] === "suspend" || parts[2] === "reactivate")) return method === "PATCH";
  if (parts.length === 1 && parts[0] === "audit-logs") return method === "GET";
  if (parts.length === 1 && parts[0] === "sessions") return method === "GET";
  if (parts.length === 2 && parts[0] === "sessions" && /^[0-9a-f-]{36}$/i.test(parts[1])) return method === "DELETE";
  if (parts.length === 2 && parts[0] === "domains" && /^[0-9a-f-]{36}$/i.test(parts[1])) return method === "DELETE";
  if (parts.length === 3 && parts[0] === "hosting-accounts" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "php") return method === "GET" || method === "PUT";
  if (parts.length === 3 && parts[0] === "hosting-accounts" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "backup-schedule") return method === "GET" || method === "PUT";
  if (parts.length === 2 && parts[0] === "organizations" && /^[0-9a-f-]{36}$/i.test(parts[1])) return method === "PUT";
  if (parts.length === 3 && parts[0] === "auth" && parts[1] === "mfa" && ["enroll", "verify", "disable"].includes(parts[2])) return method === "POST";
  if (parts.length === 2 && parts[0] === "auth" && parts[1] === "verify-email") return method === "POST";
  if (parts.length === 2 && parts[0] === "auth" && parts[1] === "resend-verification") return method === "POST";
  if (parts.length === 3 && parts[0] === "auth" && parts[1] === "login" && parts[2] === "mfa") return method === "POST";
  if (parts.length === 2 && parts[0] === "hosting-accounts" && /^[0-9a-f-]{36}$/i.test(parts[1])) return method === "DELETE";
  if (parts.length === 2 && parts[0] === "applications" && parts[1] === "runtime-profiles") return method === "GET";
  if (parts.length === 4 && parts[0] === "applications" && parts[1] === "projects" &&
      /^[0-9a-f-]{36}$/i.test(parts[2]) && parts[3] === "settings") return method === "GET" || method === "PUT";
  if (parts.length === 4 && parts[0] === "applications" && parts[1] === "projects" &&
      /^[0-9a-f-]{36}$/i.test(parts[2]) && parts[3] === "usage") return method === "GET";
  if (parts.length === 2 && parts[0] === "github" && parts[1] === "connection") return method === "GET" || method === "DELETE";
  if (parts.length === 2 && parts[0] === "github" && ["connect", "repositories", "projects"].includes(parts[1])) return method === "GET" || method === "POST";
  if (parts.length === 4 && parts[0] === "github" && parts[1] === "projects" && /^[0-9a-f-]{36}$/i.test(parts[2]) && parts[3] === "deployments") return method === "GET";
  if (parts.length === 1 && parts[0] === "dns-records") return method === "GET" || method === "POST";
  if (parts.length === 2 && parts[0] === "dns-records" && /^[a-f0-9]{32}$/i.test(parts[1])) return method === "PATCH" || method === "DELETE";
  if (parts.length === 1 && parts[0] === "overview") return method === "GET";
  if (parts.length === 1 && parts[0] === "incidents") return method === "GET";
  if (parts.length === 1 && parts[0] === "notification-settings") return true;
  if (parts.length === 2 && parts[0] === "notification-settings" && parts[1] === "test") return method === "POST";
  if (parts.length === 3 && parts[0] === "incidents" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "acknowledge") return method === "POST";
  if (parts.length === 3 && parts[0] === "hosting-plans" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "website-limit") return method === "POST";
  if (parts.length === 2 && parts[0] === "servers" && /^[0-9a-f-]{36}$/i.test(parts[1])) {
    return method === "GET";
  }
  if (parts.length === 3 && parts[0] === "domains" &&
      /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "retry") {
    return method === "POST";
  }
  if (parts.length === 3 && parts[0] === "domains" &&
      /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "dns-check") {
    return method === "GET";
  }
  if (parts.length === 3 && parts[0] === "domains" &&
      /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "cloudflare-hostname") {
    return true;
  }
  if (parts.length === 4 && parts[0] === "domains" &&
      /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "cloudflare-hostname" &&
      parts[3] === "revalidate") {
    return method === "POST";
  }
  if (parts.length === 3 && parts[0] === "servers" &&
      /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "services") {
    return method === "GET";
  }
  if (parts.length === 3 && parts[0] === "servers" &&
      /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "telemetry") {
    return method === "GET";
  }
  if (parts.length === 3 && parts[0] === "servers" &&
      /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "enrollment-token") {
    return method === "POST";
  }
  if (parts.length === 3 && parts[0] === "databases" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "users") return true;
  if (parts.length === 3 && parts[0] === "databases" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "delete") return method === "POST";
  if (parts.length === 5 && parts[0] === "databases" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "users" && /^[0-9a-f-]{36}$/i.test(parts[3]) && parts[4] === "secret") return method === "GET";
  if (parts.length === 5 && parts[0] === "databases" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "users" && /^[0-9a-f-]{36}$/i.test(parts[3]) && parts[4] === "revoke") return method === "POST";
  if (parts.length === 3 && parts[0] === "hosting-accounts" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "backups") return method === "GET" || method === "POST";
  if (parts.length === 2 && parts[0] === "backups" && /^[0-9a-f-]{36}$/i.test(parts[1])) return method === "DELETE";
  if (parts.length === 3 && parts[0] === "backups" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "restore") return method === "POST";
  if (parts.length === 3 && parts[0] === "hosting-accounts" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "files") return method === "POST";
  if (parts.length === 3 && parts[0] === "file-manager" && parts[1] === "jobs" && /^[0-9a-f-]{36}$/i.test(parts[2])) return method === "GET";
  return false;
}

async function proxy(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
  method: "GET" | "POST" | "PATCH" | "DELETE" | "PUT",
) {
  const { path } = await context.params;
  if (!Array.isArray(path) || !allowedRoute(path, method)) {
    return NextResponse.json({ message: "Not found" }, { status: 404 });
  }

  if (method !== "GET") {
    const origin = request.headers.get("origin");
    let sameOrigin = false;
    try { sameOrigin = !!origin && new URL(origin).origin === request.nextUrl.origin; }
    catch { sameOrigin = false; }
    if (!sameOrigin) return NextResponse.json({ message: "Cross-origin request rejected" }, { status: 403 });
  }

  const publicStoreRead = method === "GET" && path.length === 2 && path[0] === "store" && path[1] === "plans";
  const token = request.cookies.get(COOKIE_NAME)?.value;
  if (!token && !publicStoreRead) return NextResponse.json({ message: "Not authenticated" }, { status: 401 });

  try {
    const apiUrl = new URL(`/v1/${path.map(encodeURIComponent).join("/")}`, DEFAULT_API_BASE);
    if (apiUrl.protocol !== "https:" || apiUrl.hostname !== "api.nexoraedge.digital") {
      return NextResponse.json({ message: "Invalid Nexora API URL configuration" }, { status: 503 });
    }
    const { env } = getCloudflareContext();
    const apiService = (env as typeof env & { NEXORA_API?: ApiServiceBinding }).NEXORA_API;
    if (!apiService) throw new Error("NEXORA_API service binding is missing from nexora-dashboard");
    const upstream = await apiService.fetch(new Request(apiUrl, {
      method,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(method !== "GET" ? { "content-type": "application/json" } : {}),
      },
      ...(method !== "GET" && method !== "DELETE" ? { body: await request.text() } : {}),
      cache: "no-store",
    }));
    const response = new NextResponse(await upstream.text(), {
      status: upstream.status,
      headers: { "content-type": upstream.headers.get("content-type") ?? "application/json" },
    });
    if (upstream.status === 401) {
      response.cookies.set(COOKIE_NAME, "", {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/",
        maxAge: 0,
      });
    }
    return response;
  } catch {
    return NextResponse.json({ message: "Unable to reach the control-plane API" }, { status: 503 });
  }
}

export async function GET(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxy(request, context, "GET");
}

export async function POST(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxy(request, context, "POST");
}

export async function PATCH(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxy(request, context, "PATCH");
}

export async function DELETE(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxy(request, context, "DELETE");
}

export async function PUT(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxy(request, context, "PUT");
}
