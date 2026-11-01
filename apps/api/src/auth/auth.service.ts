import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { createHash, randomBytes } from "node:crypto";
import { PrismaService } from "../database/prisma.service";
import { hashPassword, verifyPassword } from "./password-hash";
import { signSessionToken, verifySessionToken } from "./session-token";

const SESSION_SECONDS = 15 * 60;
const MAX_LOGIN_ATTEMPTS = 8;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}

  private sessionSecret(): string {
    const secret = process.env.SESSION_SECRET;
    if (!secret || Buffer.byteLength(secret, "utf8") < 32) {
      throw new Error("SESSION_SECRET must be configured with at least 32 random bytes");
    }
    return secret;
  }

  private async issueSession(userId: string, organizationId: string, role: "OWNER" | "ADMIN" | "BILLING" | "SUPPORT" | "MEMBER") {
    const token = signSessionToken({ sub: userId, organizationId, role }, this.sessionSecret());
    const claims = verifySessionToken(token, this.sessionSecret());
    if (!claims) throw new Error("Unable to create session");
    const tokenHash = createHash("sha256").update(token).digest("hex");
    await this.prisma.authSession.create({
      data: {
        userId,
        tokenId: claims.jti,
        tokenHash,
        expiresAt: new Date(claims.exp * 1000),
      },
    });
    return {
      accessToken: token,
      tokenType: "Bearer",
      expiresIn: SESSION_SECONDS,
      organizationId,
      role,
    };
  }

  async register(input: { email: unknown; password: unknown; name: unknown; organizationName: unknown }) {
    const email = typeof input.email === "string" ? input.email.trim().toLowerCase() : "";
    const name = typeof input.name === "string" ? input.name.trim() : "";
    const organizationName = typeof input.organizationName === "string" ? input.organizationName.trim() : "";
    const password = typeof input.password === "string" ? input.password : "";

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      throw new BadRequestException("Enter a valid email address");
    }
    if (!name || name.length > 100 || !organizationName || organizationName.length > 120) {
      throw new BadRequestException("Name and organization name are required");
    }
    if (password.length < 12 || password.length > 128) {
      throw new BadRequestException("Password must be between 12 and 128 characters");
    }

    const passwordHash = await hashPassword(password);
    const baseSlug = organizationName.toLowerCase()
      .normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 42) || "workspace";
    const slug = `${baseSlug}-${randomBytes(4).toString("hex")}`;

    try {
      const result = await this.prisma.$transaction(async (tx) => {
        const user = await tx.user.create({
          data: { email, passwordHash, displayName: name, status: "ACTIVE" },
        });
        const organization = await tx.organization.create({
          data: { name: organizationName, slug },
        });
        await tx.membership.create({
          data: { userId: user.id, organizationId: organization.id, role: "OWNER" },
        });
        await tx.auditLog.create({
          data: {
            organizationId: organization.id,
            actorUserId: user.id,
            action: "auth.register",
            resourceType: "organization",
            resourceId: organization.id,
          },
        });
        return { user, organization };
      });
      const session = await this.issueSession(result.user.id, result.organization.id, "OWNER");
      return {
        user: { id: result.user.id, email: result.user.email, displayName: result.user.displayName },
        organization: { id: result.organization.id, name: result.organization.name, slug: result.organization.slug },
        ...session,
      };
    } catch (error) {
      if (typeof error === "object" && error !== null && "code" in error && error.code === "P2002") {
        throw new ConflictException("An account with this email already exists");
      }
      throw error;
    }
  }

  private async recordFailedLogin(email: string, ip: string) {
    const key = createHash("sha256").update(`${email}| ${ip}`).digest("hex");
    const now = new Date();
    const existing = await this.prisma.loginAttempt.findUnique({ where: { bucketKey: key } });
    if (!existing || now.getTime() - existing.windowStart.getTime() >= LOGIN_WINDOW_MS) {
      await this.prisma.loginAttempt.upsert({
        where: { bucketKey: key },
        create: { bucketKey: key, attempts: 1, windowStart: now, blockedUntil: null },
        update: { attempts: 1, windowStart: now, blockedUntil: null },
      });
      return;
    }
    const attempts = existing.attempts + 1;
    await this.prisma.loginAttempt.update({
      where: { bucketKey: key },
      data: {
        attempts,
        blockedUntil: attempts >= MAX_LOGIN_ATTEMPTS ? new Date(now.getTime() + LOGIN_WINDOW_MS) : null,
      },
    });
  }

  async login(input: { email: unknown; password: unknown; organizationId: unknown }, ip: string) {
    const email = typeof input.email === "string" ? input.email.trim().toLowerCase() : "";
    const password = typeof input.password === "string" ? input.password : "";
    const organizationId = typeof input.organizationId === "string" ? input.organizationId : "";
    if (!email || !password || !organizationId) {
      throw new BadRequestException("Email, password and organization ID are required");
    }
    const key = createHash("sha256").update(`${email}| ${ip}`).digest("hex");
    const limiter = await this.prisma.loginAttempt.findUnique({ where: { bucketKey: key } });
    const now = new Date();
    if (limiter?.blockedUntil && limiter.blockedUntil > now) {
      throw new UnauthorizedException("Too many sign-in attempts. Try again later.");
    }
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: {
        memberships: {
          where: { organizationId, organization: { status: "ACTIVE" } },
          select: { organizationId: true, role: true },
        },
      },
    });
    const valid = !!user?.passwordHash && user.status === "ACTIVE" &&
      user.memberships.length === 1 && await verifyPassword(password, user.passwordHash);
    if (!valid || !user) {
      await this.recordFailedLogin(email, ip);
      throw new UnauthorizedException("Invalid email, password or organization");
    }
    await this.prisma.loginAttempt.deleteMany({ where: { bucketKey: key } });
    const membership = user.memberships[0];
    const session = await this.issueSession(user.id, membership.organizationId, membership.role);
    await this.prisma.auditLog.create({
      data: {
        organizationId: membership.organizationId,
        actorUserId: user.id,
        action: "auth.login",
        resourceType: "user",
        resourceId: user.id,
        sourceIp: ip,
      },
    });
    return {
      user: { id: user.id, email: user.email, displayName: user.displayName },
      ...session,
    };
  }

  async logout(token: string) {
    const claims = verifySessionToken(token, this.sessionSecret());
    if (!claims) return { success: true };
    await this.prisma.authSession.updateMany({
      where: { tokenId: claims.jti, userId: claims.sub, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    return { success: true };
  }

  async currentUser(userId: string, organizationId: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        id: userId,
        status: "ACTIVE",
        memberships: { some: { organizationId, organization: { status: "ACTIVE" } } },
      },
      select: {
        id: true,
        email: true,
        displayName: true,
        memberships: {
          where: { organizationId },
          select: { role: true, organization: { select: { id: true, name: true, slug: true } } },
        },
      },
    });
    if (!user || user.memberships.length !== 1) throw new UnauthorizedException();
    return {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      organization: user.memberships[0].organization,
      role: user.memberships[0].role,
    };
  }
}
