import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";

const COOKIE_NAME = "nexora_session";
const COOKIE_MAX_AGE = 15 * 60;

async function apiRequest(path: string, init: RequestInit) {
  const base = process.env.NEXORA_API_URL?.replace(/\/$/, "");
  if (!base) throw new Error("NEXORA_API_URL is not configured");
  return fetch(`${base}/v1/auth/${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...init.headers },
    cache: "no-store",
  });
}

export async function POST(request: NextRequest, context: { params: Promise<{ action: string }> }) {
  const { action } = await context.params;
  if (action === "login" || action === "register") {
    try {
      const body = await request.json();
      const upstream = await apiRequest(action, { method: "POST", body: JSON.stringify(body) });
      const data = await upstream.json();
      if (!upstream.ok) return NextResponse.json(data, { status: upstream.status });
      const token = typeof data.accessToken === "string" ? data.accessToken : null;
      if (!token) return NextResponse.json({ message: "Authentication service returned no session" }, { status: 502 });
      const { accessToken: _discarded, ...safeData } = data;
      const response = NextResponse.json(safeData, { status: upstream.status });
      response.cookies.set(COOKIE_NAME, token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: COOKIE_MAX_AGE,
      });
      return response;
    } catch {
      return NextResponse.json({ message: "Unable to reach the authentication service" }, { status: 503 });
    }
  }

  if (action === "logout") {
    const token = request.cookies.get(COOKIE_NAME)?.value;
    if (token) {
      try { await apiRequest("logout", { method: "POST", headers: { authorization: `Bearer ${token}` } }); } catch { /* local cookie is still cleared */ }
    }
    const response = NextResponse.json({ success: true });
    response.cookies.set(COOKIE_NAME, "", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", path: "/", maxAge: 0 });
    return response;
  }

  return NextResponse.json({ message: "Not found" }, { status: 404 });
}

export async function GET(_request: NextRequest, context: { params: Promise<{ action: string }> }) {
  const { action } = await context.params;
  if (action !== "me") return NextResponse.json({ message: "Not found" }, { status: 404 });
  const token = _request.cookies.get(COOKIE_NAME)?.value;
  if (!token) return NextResponse.json({ message: "Not authenticated" }, { status: 401 });
  try {
    const upstream = await apiRequest("me", { method: "GET", headers: { authorization: `Bearer ${token}` } });
    const data = await upstream.json();
    if (!upstream.ok) {
      const response = NextResponse.json(data, { status: upstream.status });
      if (upstream.status === 401) response.cookies.set(COOKIE_NAME, "", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", path: "/", maxAge: 0 });
      return response;
    }
    return NextResponse.json(data);
  } catch {
    return NextResponse.json({ message: "Unable to reach the authentication service" }, { status: 503 });
  }
}
