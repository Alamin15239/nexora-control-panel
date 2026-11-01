import { Controller, Get } from "@nestjs/common";

@Controller("health")
export class HealthController {
  @Get()
  getHealth() {
    return {
      status: "ok",
      service: "nexora-control-api",
      stage: "foundation",
      timestamp: new Date().toISOString(),
    };
  }
}
