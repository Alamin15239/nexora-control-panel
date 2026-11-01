import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  SetMetadata,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { SessionClaims } from "./session-token";

export const REQUIRED_ROLES = "nexora:required-roles";
export type MembershipRole = SessionClaims["role"];
export const RequireRoles = (...roles: MembershipRole[]) => SetMetadata(REQUIRED_ROLES, roles);

interface AuthenticatedRequest {
  user?: SessionClaims;
}

export function hasRequiredRole(
  actual: MembershipRole | undefined,
  required: readonly MembershipRole[],
): boolean {
  return !!actual && (required.length === 0 || required.includes(actual));
}

@Injectable()
export class MembershipRolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<MembershipRole[]>(REQUIRED_ROLES, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!required?.length) return true;

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    if (!hasRequiredRole(request.user?.role, required)) {
      throw new ForbiddenException("Your organization role cannot perform this action");
    }
    return true;
  }
}
