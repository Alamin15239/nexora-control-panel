import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { createHash } from "node:crypto";
import { PrismaService } from "../database/prisma.service";
import { verifySessionToken, SessionClaims } from "./session-token";

interface AuthenticatedRequest {
  headers: { authorization?: string };
  user?: SessionClaims;
}

@Injectable()
export class SessionAuthGuard implements CanActivate {
  constructor(private readonly prisma: PrismaService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const authorization = request.headers.authorization;
    if (!authorization || !authorization.startsWith("Bearer ")) {
      throw new UnauthorizedException("A valid bearer session is required");
    }

    const token = authorization.slice(7).trim();
    const secret = process.env.SESSION_SECRET;
    if (!secret) {
      throw new UnauthorizedException("Authentication is not configured");
    }

    const claims = verifySessionToken(token, secret);
    if (!claims) {
      throw new UnauthorizedException("Session is invalid or expired");
    }

    const tokenHash = createHash("sha256").update(token).digest("hex");
    const session = await this.prisma.authSession.findFirst({
      where: {
        tokenId: claims.jti,
        tokenHash,
        userId: claims.sub,
        revokedAt: null,
        expiresAt: { gt: new Date() },
        user: {
          status: "ACTIVE",
          memberships: {
            some: {
              organizationId: claims.organizationId,
              role: claims.role,
              organization: { status: "ACTIVE" },
            },
          },
        },
      },
      select: { id: true },
    });

    if (!session) {
      throw new UnauthorizedException("Session has been revoked or access changed");
    }

    request.user = claims;
    return true;
  }
}
