import { Hono } from "hono";

type Bindings = {
  DB: D1Database;
};

const app = new Hono<{ Bindings: Bindings }>();

app.get("/v1/health", (c) =>
  c.json({
    service: "nexora-api",
    status: "ok",
    runtime: "cloudflare-workers",
  }),
);

app.get("/v1/health/ready", async (c) => {
  try {
    await c.env.DB.prepare("SELECT 1").first();
    return c.json({ status: "ready", database: "connected" });
  } catch {
    return c.json(
      { status: "not_ready", database: "unavailable" },
      503,
    );
  }
});

app.notFound((c) => c.json({ error: "Not found" }, 404));

export default app;
