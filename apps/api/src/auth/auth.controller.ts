import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Ip,
  Post,
  Req,
  UseGuards,
} from "@nestjs/common";
import { AuthService } from "./auth.service";
import { SessionAuthGuard } from "./auth.guard";
import { SessionClaims } from "./session-token";

interface AuthenticatedRequest {
  user: SessionClaims;
}

@Controller("auth")
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post("register")
  register(@Body() body: { email?: unknown; password?: unknown; name?: unknown; organizationName?: unknown }) {
    return this.auth.register({
      email: body.email,
      password: body.password,
      name: body.name,
      organizationName: body.organizationName,
    });
  }

  @Post("login")
  @HttpCode(HttpStatus.OK)
  login(@Body() body: { email?: unknown; password?: unknown; organizationId?: unknown }, @Ip() ip: string) {
    return this.auth.login({
      email: body.email,
      password: body.password,
      organizationId: body.organizationId,
    }, ip || "unknown");
  }

  @Post("logout")
  @UseGuards(SessionAuthGuard)
  @HttpCode(HttpStatus.OK)
  logout(@Headers("authorization") authorization?: string) {
    return this.auth.logout((authorization ?? "").slice(7).trim());
  }

  @Get("me")
  @UseGuards(SessionAuthGuard)
  me(@Req() request: AuthenticatedRequest) {
    return this.auth.currentUser(request.user.sub, request.user.organizationId);
  }
}
