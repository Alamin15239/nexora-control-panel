import { NextRequest, NextResponse } from "next/server";
import { getCloudflareContext } from "@opennextjs/cloudflare";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const DEFAULT_API_BASE = "https://nexora-api.alamin-kha-saadfreeh.workers.dev";
type ApiServiceBinding = { fetch(request: Request): Promise<Response> };

const COOKIE_NAME = "nexora_session";

function allowedRoute(parts: string[], method: "GET" | "POST"): boolean {
  if (parts.length === 1 && ["servers", "hosting-plans", "hosting-accounts", "domains", "databases"].includes(parts[0])) return true;
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
  if (parts.length === 3 && parts[0] === "hosting-accounts" && /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "files") return method === "POST";
  if (parts.length === 3 && parts[0] === "file-manager" && parts[1] === "jobs" && /^[0-9a-f-]{36}$/i.test(parts[2])) return method === "GET";
  return false;
}

async function proxy(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
  method: "GET" | "POST",
) {
  const { path } = await context.params;
  if (!Array.isArray(path) || !allowedRoute(path, method)) {
    return NextResponse.json({ message: "Not found" }, { status: 404 });
  }

  if (method === "POST") {
    const origin = request.headers.get("origin");
    let sameOrigin = false;
    try { sameOrigin = !!origin && new URL(origin).origin === request.nextUrl.origin; }
    catch { sameOrigin = false; }
    if (!sameOrigin) return NextResponse.json({ message: "Cross-origin request rejected" }, { status: 403 });
  }

  const token = request.cookies.get(COOKIE_NAME)?.value;
  if (!token) return NextResponse.json({ message: "Not authenticated" }, { status: 401 });

  try {
    const apiUrl = new URL(`/v1/${path.map(encodeURIComponent).join("/")}`, DEFAULT_API_BASE);
    if (apiUrl.protocol !== "https:" || !apiUrl.hostname.endsWith(".workers.dev")) {
      return NextResponse.json({ message: "Invalid Nexora API URL configuration" }, { status: 503 });
    }
    const { env } = getCloudflareContext();
    const apiService = (env as typeof env & { NEXORA_API?: ApiServiceBinding }).NEXORA_API;
    if (!apiService) throw new Error("NEXORA_API service binding is missing from nexora-dashboard");
    const upstream = await apiService.fetch(new Request(apiUrl, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(method === "POST" ? { "content-type": "application/json" } : {}),
      },
      ...(method === "POST" ? { body: await request.text() } : {}),
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
