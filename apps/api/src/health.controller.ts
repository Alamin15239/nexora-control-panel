import {
  Controller,
  Get,
  ServiceUnavailableException,
} from "@nestjs/common";
import { PrismaService } from "./database/prisma.service";

@Controller("health")
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  // Liveness: confirms that the API process is running.
  @Get()
  getHealth() {
    return {
      status: "ok",
      service: "nexora-control-api",
      stage: "database-integration",
      timestamp: new Date().toISOString(),
    };
  }

  // Readiness: confirms that the API can reach its configured PostgreSQL database.
  @Get("ready")
  async getReadiness() {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return {
        status: "ready",
        service: "nexora-control-api",
        dependencies: { database: "connected" },
        timestamp: new Date().toISOString(),
      };
    } catch {
      throw new ServiceUnavailableException({
        status: "not_ready",
        service: "nexora-control-api",
        dependencies: { database: "unavailable" },
        timestamp: new Date().toISOString(),
      });
    }
  }
}