export type DnsRecordType = "A" | "AAAA" | "CNAME" | "MX" | "TXT" | "CAA";

export type DnsRecord = {
  id: string;
  type: DnsRecordType;
  name: string;
  content: string;
  ttl: number;
  proxied: boolean;
  priority?: number;
  comment?: string;
};

type DnsBindings = {
  CLOUDFLARE_DNS_API_TOKEN?: string;
  CLOUDFLARE_ZONE_ID?: string;
  CLOUDFLARE_ZONE_NAME?: string;
};

type CloudflareResponse<T> = {
  success?: boolean;
  errors?: Array<{ message?: string }>;
  result?: T;
};

function zonePath(env: DnsBindings, suffix = ""): string {
  if (!env.CLOUDFLARE_DNS_API_TOKEN || !env.CLOUDFLARE_ZONE_ID || !env.CLOUDFLARE_ZONE_NAME) {
    throw new Error("DNS integration is not configured. Verify CLOUDFLARE_DNS_API_TOKEN, CLOUDFLARE_ZONE_ID and CLOUDFLARE_ZONE_NAME.");
  }
  return "/zones/" + encodeURIComponent(env.CLOUDFLARE_ZONE_ID) + "/dns_records" + suffix;
}

async function request<T>(
  env: DnsBindings,
  path: string,
  method: "GET" | "POST" | "PATCH" | "DELETE" = "GET",
  body?: Record<string, unknown>,
): Promise<T> {
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
  const payload = await response.json() as CloudflareResponse<T>;
  if (!response.ok || payload.success !== true) {
    const detail = payload.errors?.map((item) => item.message).filter(Boolean).join("; ");
    throw new Error(detail || "Cloudflare DNS API returned HTTP " + response.status);
  }
  return payload.result as T;
}

function normalizedName(raw: unknown, zoneName: string, allowUnderscore = false): string {
  if (typeof raw !== "string") throw new Error("A DNS record name is required.");
  const name = raw.trim().toLowerCase().replace(/\.$/, "");
  const zone = zoneName.toLowerCase().replace(/\.$/, "");
  if (!name || name.length > 253 || (name !== zone && !name.endsWith("." + zone))) {
    throw new Error("Record name must be the zone apex or a subdomain of " + zone + ".");
  }
  const validLabel = (part: string) =>
    /^(?:\*|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$/.test(part) ||
    (allowUnderscore && /^_[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?$/.test(part));
  if (name.split(".").some((part) => !validLabel(part))) {
    throw new Error("DNS record name contains an invalid label.");
  }
  return name;
}

function normalizeRecord(input: Record<string, unknown>, env: DnsBindings): Record<string, unknown> {
  const zone = (env.CLOUDFLARE_ZONE_NAME ?? "").trim().toLowerCase();
  if (!zone) throw new Error("CLOUDFLARE_ZONE_NAME is not configured.");
  const type = typeof input.type === "string" ? input.type.toUpperCase() : "";
  if (!["A", "AAAA", "CNAME", "MX", "TXT", "CAA"].includes(type)) {
    throw new Error("Supported DNS types are A, AAAA, CNAME, MX, TXT and CAA.");
  }
  const name = normalizedName(input.name, zone, type === "TXT");
  const content = typeof input.content === "string" ? input.content.trim() : "";
  if (!content || content.length > 2048) throw new Error("Record content is required and must be 2,048 characters or fewer.");
  if (type === "A" && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(content)) throw new Error("Enter a valid IPv4 address for an A record.");
  if (type === "AAAA") {
    try { new URL("http://[" + content + "]/"); }
    catch { throw new Error("Enter a valid IPv6 address for an AAAA record."); }
  }
  if (type === "CNAME" || type === "MX") {
    const target = content.replace(/\.$/, "");
    if (target.length > 253 || !target.split(".").every((part) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(part))) {
      throw new Error("Enter a valid hostname as the record target.");
    }
  }
  if (type === "CNAME" && name === zone) throw new Error("A CNAME cannot be created at the zone apex.");
  if (type === "TXT" && content.length > 2048) throw new Error("TXT content is too long.");
  if (type === "CAA" && !/^\d+\s+(?:issue|issuewild|iodef)\s+.+$/i.test(content)) {
    throw new Error("CAA content must use the format: flags tag value.");
  }
  const proxied = input.proxied === true;
  const ttl = proxied ? 1 : input.ttl === 1 ? 1 : Number(input.ttl ?? 3600);
  if (!Number.isInteger(ttl) || (ttl !== 1 && (ttl < 60 || ttl > 86400))) throw new Error("TTL must be Auto or between 60 and 86,400 seconds.");
  if (proxied && !["A", "AAAA", "CNAME"].includes(type)) throw new Error("Proxy status is only available for A, AAAA and CNAME records.");
  const record: Record<string, unknown> = { type, name, content, ttl, proxied };
  if (type === "MX") {
    const priority = Number(input.priority);
    if (!Number.isInteger(priority) || priority < 0 || priority > 65535) throw new Error("MX priority must be between 0 and 65,535.");
    record.priority = priority;
  }
  if (typeof input.comment === "string" && input.comment.trim()) record.comment = input.comment.trim().slice(0, 500);
  return record;
}

export async function listDnsRecords(env: DnsBindings): Promise<DnsRecord[]> {
  const path = zonePath(env);
  const records: DnsRecord[] = [];
  let page = 1;
  while (page <= 20) {
    const query = new URLSearchParams({ per_page: "100", page: String(page), order: "type", direction: "asc" });
    const response = await request<DnsRecord[] & { result_info?: { total_pages?: number } }>(env, path + "?" + query.toString());
    const batch = Array.isArray(response) ? response : [];
    records.push(...batch);
    if (batch.length < 100) break;
    page++;
  }
  return records;
}

export async function createDnsRecord(env: DnsBindings, input: Record<string, unknown>): Promise<DnsRecord> {
  return request<DnsRecord>(env, zonePath(env), "POST", normalizeRecord(input, env));
}

export async function updateDnsRecord(env: DnsBindings, id: string, input: Record<string, unknown>): Promise<DnsRecord> {
  if (!/^[a-f0-9]{32}$/i.test(id)) throw new Error("Invalid DNS record identifier.");
  return request<DnsRecord>(env, zonePath(env, "/" + encodeURIComponent(id)), "PATCH", normalizeRecord(input, env));
}

export async function deleteDnsRecord(env: DnsBindings, id: string): Promise<void> {
  if (!/^[a-f0-9]{32}$/i.test(id)) throw new Error("Invalid DNS record identifier.");
  await request<unknown>(env, zonePath(env, "/" + encodeURIComponent(id)), "DELETE");
}
