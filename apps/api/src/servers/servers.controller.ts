import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Req,
  UseGuards,
} from "@nestjs/common";
import { SessionAuthGuard } from "../auth/auth.guard";
import { MembershipRolesGuard, RequireRoles } from "../auth/roles.guard";
import { SessionClaims } from "../auth/session-token";
import { ServersService } from "./servers.service";

interface AuthenticatedRequest { user: SessionClaims }

@Controller("servers")
@UseGuards(SessionAuthGuard, MembershipRolesGuard)
export class ServersController {
  constructor(private readonly servers: ServersService) {}

  @Get()
  list(@Req() request: AuthenticatedRequest) {
    return this.servers.list(request.user);
  }

  @Get(":id")
  get(@Req() request: AuthenticatedRequest, @Param("id") id: string) {
    return this.servers.get(request.user, id);
  }

  @Post()
  @RequireRoles("OWNER", "ADMIN")
  create(@Req() request: AuthenticatedRequest, @Body() body: { hostname?: unknown; primaryIp?: unknown; region?: unknown }) {
    return this.servers.create(request.user, body);
  }

  @Post(":id/enrollment-token")
  @RequireRoles("OWNER", "ADMIN")
  issueEnrollmentToken(@Req() request: AuthenticatedRequest, @Param("id") id: string) {
    return this.servers.issueEnrollmentToken(request.user, id);
  }
}
