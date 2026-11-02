import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { isIP } from "node:net";
import { randomUUID } from "node:crypto";
import { PrismaService } from "../database/prisma.service";
import { SessionClaims } from "../auth/session-token";
import { createEnrollmentToken } from "./enrollment-token";

@Injectable()
export class ServersService {
  constructor(private readonly prisma: PrismaService) {}

  async list(user: SessionClaims) {
    return this.prisma.server.findMany({
      where: { organizationId: user.organizationId },
      orderBy: { createdAt: "desc" },
      select: {
        id: true, hostname: true, primaryIp: true, region: true,
        agentVersion: true, status: true, lastHeartbeatAt: true,
        createdAt: true, updatedAt: true,
      },
    });
  }

  async get(user: SessionClaims, serverId: string) {
    const server = await this.prisma.server.findFirst({
      where: { id: serverId, organizationId: user.organizationId },
      select: {
        id: true, hostname: true, primaryIp: true, region: true,
        agentVersion: true, status: true, lastHeartbeatAt: true,
        createdAt: true, updatedAt: true,
      },
    });
    if (!server) throw new NotFoundException("Server not found");
    return server;
  }

  async create(user: SessionClaims, input: { hostname?: unknown; primaryIp?: unknown; region?: unknown }) {
    const hostname = typeof input.hostname === "string" ? input.hostname.trim().toLowerCase() : "";
    const primaryIp = typeof input.primaryIp === "string" ? input.primaryIp.trim() : "";
    const region = typeof input.region === "string" ? input.region.trim() : "";

    if (hostname.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/.test(hostname)) {
      throw new BadRequestException("Enter a valid server hostname");
    }
    if (!isIP(primaryIp)) throw new BadRequestException("Enter a valid IPv4 or IPv6 address");
    if (region.length > 80) throw new BadRequestException("Region must be 80 characters or fewer");

    const server = await this.prisma.$transaction(async (tx) => {
      const created = await tx.server.create({
        data: {
          organizationId: user.organizationId,
          hostname,
          primaryIp,
          region: region || null,
        },
        select: {
          id: true, hostname: true, primaryIp: true, region: true,
          agentVersion: true, status: true, lastHeartbeatAt: true,
          createdAt: true, updatedAt: true,
        },
      });
      await tx.auditLog.create({
        data: {
          organizationId: user.organizationId,
          actorUserId: user.sub,
          action: "server.created",
          resourceType: "server",
          resourceId: created.id,
          metadata: { hostname: created.hostname, primaryIp: created.primaryIp },
        },
      });
      return created;
    });
    return server;
  }

  async issueEnrollmentToken(user: SessionClaims, serverId: string) {
    const server = await this.prisma.server.findFirst({
      where: { id: serverId, organizationId: user.organizationId },
      select: { id: true, hostname: true },
    });
    if (!server) throw new NotFoundException("Server not found");

    const { token, tokenHash } = createEnrollmentToken();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    await this.prisma.$transaction(async (tx) => {
      await tx.agentEnrollment.upsert({
        where: { serverId: server.id },
        create: {
          organizationId: user.organizationId,
          serverId: server.id,
          tokenHash,
          expiresAt,
        },
        update: {
          tokenHash,
          expiresAt,
          consumedAt: null,
          organizationId: user.organizationId,
        },
      });
      await tx.auditLog.create({
        data: {
          organizationId: user.organizationId,
          actorUserId: user.sub,
          action: "server.enrollment_token_issued",
          resourceType: "server",
          resourceId: server.id,
          metadata: { expiresAt: expiresAt.toISOString() },
        },
      });
    });

    return {
      serverId: server.id,
      hostname: server.hostname,
      enrollmentToken: token,
      expiresAt: expiresAt.toISOString(),
      expiresInSeconds: 900,
      warning: "This token is shown only once. Store it securely and never share it in logs.",
    };
  }
}
