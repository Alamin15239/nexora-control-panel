import { Global, Module } from "@nestjs/common";
import { SessionAuthGuard } from "./auth.guard";
import { MembershipRolesGuard } from "./roles.guard";
import { AuthService } from "./auth.service";
import { AuthController } from "./auth.controller";

@Global()
@Module({
  controllers: [AuthController],
  providers: [SessionAuthGuard, MembershipRolesGuard, AuthService],
  exports: [SessionAuthGuard, MembershipRolesGuard, AuthService],
})
export class AuthModule {}
