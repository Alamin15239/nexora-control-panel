import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const DEFAULT_API_BASE = "https://nexora-api.alamin-kha-saadfreeh.workers.dev";

const COOKIE_NAME = "nexora_session";

function allowedRoute(parts: string[], method: "GET" | "POST"): boolean {
  if (parts.length === 1 && parts[0] === "servers") return true;
  if (parts.length === 2 && parts[0] === "servers" && /^[0-9a-f-]{36}$/i.test(parts[1])) {
    return method === "GET";
  }
  if (parts.length === 3 && parts[0] === "servers" &&
      /^[0-9a-f-]{36}$/i.test(parts[1]) && parts[2] === "enrollment-token") {
    return method === "POST";
  }
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

  const token = request.cookies.get(COOKIE_NAME)?.value;
  if (!token) return NextResponse.json({ message: "Not authenticated" }, { status: 401 });

  const base = DEFAULT_API_BASE;

  try {
    const apiUrl = new URL(`/v1/${path.map(encodeURIComponent).join("/")}`, base);
    if (apiUrl.protocol !== "https:" || !apiUrl.hostname.endsWith(".workers.dev")) {
      return NextResponse.json({ message: "Invalid Nexora API URL configuration" }, { status: 503 });
    }
    const upstream = await fetch(apiUrl, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(method === "POST" ? { "content-type": "application/json" } : {}),
      },
      ...(method === "POST" ? { body: await request.text() } : {}),
      cache: "no-store",
    });
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
