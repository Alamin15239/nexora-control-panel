import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const COOKIE_NAME = "nexora_session";
const COOKIE_MAX_AGE = 15 * 60;
const DEFAULT_API_BASE = "https://nexora-api.alamin-kha-saadfreeh.workers.dev";

function getApiBase(): string {
  // Keep auth traffic pinned to the independently deployed API Worker.
  // A dashboard-level variable must not silently redirect authentication
  // requests to the dashboard Worker or an outdated endpoint.
  return DEFAULT_API_BASE;
}

async function apiRequest(path: string, init: RequestInit): Promise<Response> {
  const base = getApiBase();
  return fetch(new URL(`/v1/auth/${path}`, base), {
    ...init,
    headers: { "content-type": "application/json", ...init.headers },
    cache: "no-store",
    redirect: "error",
  });
}

async function readApiResponse(response: Response): Promise<Record<string, unknown>> {
  const contentType = response.headers.get("content-type") ?? "";
  const text = await response.text();
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error(`Authentication API returned HTTP ${response.status} with content-type "${contentType}" and body "${text.slice(0, 240)}"`);
  }
  try {
    const parsed: unknown = JSON.parse(text);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("API JSON response was not an object");
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    throw new Error(`Authentication API returned invalid JSON (HTTP ${response.status}): ${error instanceof Error ? error.message : "parse error"}`);
  }
}

export async function POST(request: NextRequest, context: { params: Promise<{ action: string }> }) {
  const { action } = await context.params;

  if (action === "login" || action === "register") {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json({ message: "Invalid request body" }, { status: 400 });
    }

    let upstream: Response;
    try {
      upstream = await apiRequest(action, { method: "POST", body: JSON.stringify(body) });
    } catch (error) {
      console.error("[Nexora auth proxy] API request failed:", { target: DEFAULT_API_BASE, reason: error instanceof Error ? error.message : String(error) });
      return NextResponse.json({ message: "Unable to connect to the Nexora API. Check the dashboard Worker API URL and deployment." }, { status: 503 });
    }

    let data: Record<string, unknown>;
    try {
      data = await readApiResponse(upstream);
    } catch (error) {
      console.error("[Nexora auth proxy] Invalid API response:", error);
      return NextResponse.json({ message: "The Nexora API returned an invalid response. Check the dashboard Worker logs for the upstream response details." }, { status: 502 });
    }

    if (!upstream.ok) return NextResponse.json(data, { status: upstream.status });

    const token = typeof data.accessToken === "string" ? data.accessToken : null;
    if (!token) return NextResponse.json({ message: "Authentication service returned no session" }, { status: 502 });

    const { accessToken: _discarded, ...safeData } = data;
    const response = NextResponse.json(safeData, { status: upstream.status });
    response.cookies.set(COOKIE_NAME, token, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
      maxAge: COOKIE_MAX_AGE,
    });
    return response;
  }

  if (action === "logout") {
    const token = request.cookies.get(COOKIE_NAME)?.value;
    if (token) {
      try {
        await apiRequest("logout", { method: "POST", headers: { authorization: `Bearer ${token}` } });
      } catch (error) {
        console.error("[Nexora auth proxy] Logout request failed:", error);
      }
    }
    const response = NextResponse.json({ success: true });
    response.cookies.set(COOKIE_NAME, "", { httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 0 });
    return response;
  }

  return NextResponse.json({ message: "Not found" }, { status: 404 });
}

export async function GET(request: NextRequest, context: { params: Promise<{ action: string }> }) {
  const { action } = await context.params;
  if (action !== "me") return NextResponse.json({ message: "Not found" }, { status: 404 });

  const token = request.cookies.get(COOKIE_NAME)?.value;
  if (!token) return NextResponse.json({ message: "Not authenticated" }, { status: 401 });

  let upstream: Response;
  try {
    upstream = await apiRequest("me", { method: "GET", headers: { authorization: `Bearer ${token}` } });
  } catch (error) {
    console.error("[Nexora auth proxy] Session request failed:", { target: DEFAULT_API_BASE, reason: error instanceof Error ? error.message : String(error) });
    return NextResponse.json({ message: "Unable to connect to the Nexora API." }, { status: 503 });
  }

  let data: Record<string, unknown>;
  try {
    data = await readApiResponse(upstream);
  } catch (error) {
    console.error("[Nexora auth proxy] Invalid session response:", error);
    return NextResponse.json({ message: "The Nexora API returned an invalid response." }, { status: 502 });
  }

  if (!upstream.ok) {
    const response = NextResponse.json(data, { status: upstream.status });
    if (upstream.status === 401) {
      response.cookies.set(COOKIE_NAME, "", { httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 0 });
    }
    return response;
  }

  return NextResponse.json(data);
}
