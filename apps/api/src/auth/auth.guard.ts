import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { verifySessionToken, SessionClaims } from "./session-token";

interface AuthenticatedRequest {
  headers: { authorization?: string };
  user?: SessionClaims;
}

@Injectable()
export class SessionAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
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

    request.user = claims;
    return true;
  }
}
