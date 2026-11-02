import { NextRequest, NextResponse } from "next/server";

const API_BASE =
  process.env.NEXORA_API_URL ||
  "https://nexora-api.alamin-kha-saadfreeh.workers.dev";

const SESSION_COOKIE = "nexora_session";
const SESSION_MAX_AGE = 15 * 60;

function readSession(request: NextRequest): string {
  return request.cookies.get(SESSION_COOKIE)?.value ?? "";
}

async function upstream(path: string, init: RequestInit = {}) {
  return fetch(`${API_BASE.replace(/\/$/, "")}${path}`, {
    ...init,
    cache: "no-store",
    headers: {
      ...(init.body ? { "content-type": "application/json" } : {}),
      ...init.headers,
    },
  });
}

async function jsonResponse(response: Response) {
  const body = await response.text();
  return new NextResponse(body || "{}", {
    status: response.status,
    headers: { "content-type": response.headers.get("content-type") ?? "application/json" },
  });
}

export async function POST(request: NextRequest, context: { params: Promise<{ segments: string[] }> }) {
  const { segments } = await context.params;
  const action = segments.join("/");
  if (!["login", "register", "logout"].includes(action)) {
    return NextResponse.json({ message: "Authentication route not found" }, { status: 404 });
  }

  if (action === "logout") {
    const token = readSession(request);
    if (token) {
      await upstream("/v1/auth/logout", {
        method: "POST",
        headers: { authorization: `Bearer ${token}` },
      }).catch(() => undefined);
    }
    const response = NextResponse.json({ success: true });
    response.cookies.set(SESSION_COOKIE, "", {
      httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 0,
    });
    return response;
  }

  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    return NextResponse.json({ message: "Invalid JSON request" }, { status: 400 });
  }

  let result: Response;
  try {
    result = await upstream(`/v1/auth/${action}`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  } catch {
    return NextResponse.json({ message: "Unable to reach the authentication service" }, { status: 503 });
  }

  const body = await result.text();
  const response = new NextResponse(body || "{}", {
    status: result.status,
    headers: { "content-type": result.headers.get("content-type") ?? "application/json" },
  });

  if (action === "login" && result.ok) {
    try {
      const data = JSON.parse(body) as { accessToken?: string };
      if (data.accessToken) {
        response.cookies.set(SESSION_COOKIE, data.accessToken, {
          httpOnly: true,
          secure: true,
          sameSite: "lax",
          path: "/",
          maxAge: SESSION_MAX_AGE,
        });
      }
    } catch {
      return NextResponse.json({ message: "Invalid authentication response" }, { status: 502 });
    }
  }

  return response;
}

export async function GET(request: NextRequest, context: { params: Promise<{ segments: string[] }> }) {
  const { segments } = await context.params;
  if (segments.join("/") !== "me") {
    return NextResponse.json({ message: "Authentication route not found" }, { status: 404 });
  }
  const token = readSession(request);
  if (!token) return NextResponse.json({ message: "Not authenticated" }, { status: 401 });

  try {
    const result = await upstream("/v1/auth/me", {
      headers: { authorization: `Bearer ${token}` },
    });
    return jsonResponse(result);
  } catch {
    return NextResponse.json({ message: "Unable to reach the authentication service" }, { status: 503 });
  }
}
