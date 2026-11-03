type DnsBindings = {
  CLOUDFLARE_DNS_API_TOKEN?: string;
  CLOUDFLARE_ZONE_ID?: string;
  CLOUDFLARE_ZONE_NAME?: string;
};

type CloudflareDnsRecord = {
  id: string;
  type: string;
  name: string;
  content: string;
  proxied: boolean;
};

type CloudflareDnsResponse<T> = {
  success?: boolean;
  errors?: Array<{ message?: string }>;
  result?: T;
};

async function cloudflareDnsRequest<T>(
  env: DnsBindings,
  path: string,
  method: "GET" | "POST" | "PATCH" = "GET",
  body?: Record<string, unknown>,
): Promise<T> {
  if (!env.CLOUDFLARE_DNS_API_TOKEN || !env.CLOUDFLARE_ZONE_ID) {
    throw new Error("DNS automation is not configured. Add CLOUDFLARE_DNS_API_TOKEN with DNS:Edit permission for the Nexora zone.");
  }
  const response = await fetch("https://api.cloudflare.com/client/v4" + path, {
    method,
    headers: {
      authorization: "Bearer " + env.CLOUDFLARE_DNS_API_TOKEN,
      accept: "application/json",
      ...(body ? { "content-type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(12000),
  });
  const payload = await response.json() as CloudflareDnsResponse<T>;
  if (!response.ok || payload.success !== true || payload.result === undefined) {
    const detail = payload.errors?.map((item) => item.message).filter(Boolean).join("; ");
    throw new Error(detail || "Cloudflare DNS API returned HTTP " + response.status);
  }
  return payload.result;
}

export type SaasDnsProvisioningResult = {
  status: "CREATED" | "ALREADY_CONFIGURED" | "UPDATED" | "CUSTOMER_DNS_REQUIRED" | "MANUAL_REQUIRED";
  hostname: string;
  target: string;
  proxied?: boolean;
  message: string;
};

export async function ensureSaasDnsRecord(
  env: DnsBindings,
  rawHostname: string,
  rawTarget: string,
): Promise<SaasDnsProvisioningResult> {
  const hostname = rawHostname.trim().toLowerCase().replace(/\.$/, "");
  const target = rawTarget.trim().toLowerCase().replace(/\.$/, "");
  const zoneName = (env.CLOUDFLARE_ZONE_NAME || "").trim().toLowerCase();
  if (!zoneName) throw new Error("Set CLOUDFLARE_ZONE_NAME in the Worker configuration.");
  if (hostname === zoneName || !hostname.endsWith("." + zoneName)) {
    return {
      status: "CUSTOMER_DNS_REQUIRED",
      hostname,
      target,
      message: "This hostname is outside Nexora's managed DNS zone. The customer must create a CNAME pointing to " + target + ".",
    };
  }

  const query = new URLSearchParams({ name: hostname });
  const records = await cloudflareDnsRequest<CloudflareDnsRecord[]>(
    env,
    "/zones/" + encodeURIComponent(env.CLOUDFLARE_ZONE_ID!) + "/dns_records?" + query.toString(),
  );
  const existing = records ?? [];
  if (existing.length > 1 || (existing.length === 1 && existing[0].type !== "CNAME")) {
    throw new Error("A conflicting DNS record already exists for " + hostname + ". Remove or change it before automatic CNAME provisioning.");
  }
  if (existing.length === 1) {
    const record = existing[0];
    if (record.content.toLowerCase().replace(/\.$/, "") !== target) {
      throw new Error("A CNAME already exists for " + hostname + " but points to a different target. No DNS record was changed.");
    }
    if (record.proxied) {
      return { status: "ALREADY_CONFIGURED", hostname, target, proxied: true, message: "The customer CNAME already points to the SaaS target and is proxied." };
    }
    await cloudflareDnsRequest<CloudflareDnsRecord>(
      env,
      "/zones/" + encodeURIComponent(env.CLOUDFLARE_ZONE_ID!) + "/dns_records/" + encodeURIComponent(record.id),
      "PATCH",
      { proxied: true },
    );
    return { status: "UPDATED", hostname, target, proxied: true, message: "The existing matching CNAME was changed to proxied." };
  }

  await cloudflareDnsRequest<CloudflareDnsRecord>(
    env,
    "/zones/" + encodeURIComponent(env.CLOUDFLARE_ZONE_ID!) + "/dns_records",
    "POST",
    { type: "CNAME", name: hostname, content: target, ttl: 1, proxied: true },
  );
  return { status: "CREATED", hostname, target, proxied: true, message: "The proxied customer CNAME was created automatically." };
}
