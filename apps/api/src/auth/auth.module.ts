import { Global, Module } from "@nestjs/common";
import { SessionAuthGuard } from "./auth.guard";
import { MembershipRolesGuard } from "./roles.guard";

@Global()
@Module({
  providers: [SessionAuthGuard, MembershipRolesGuard],
  exports: [SessionAuthGuard, MembershipRolesGuard],
})
export class AuthModule {}
