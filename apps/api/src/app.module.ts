import { Module } from "@nestjs/common";
import { HealthController } from "./health.controller";
import { PrismaModule } from "./database/prisma.module";
import { AuthModule } from "./auth/auth.module";
import { ServersModule } from "./servers/servers.module";

@Module({
  imports: [PrismaModule, AuthModule, ServersModule],
  controllers: [HealthController],
})
export class AppModule {}
