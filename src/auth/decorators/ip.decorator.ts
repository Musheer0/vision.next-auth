import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { Request } from "express";

export const Ip = createParamDecorator((data: unknown, ctx: ExecutionContext) => {
  const request: Request = ctx.switchToHttp().getRequest();
  const forwarded = request.headers['x-forwarded-for'];

  const ip = typeof forwarded === 'string' ? forwarded.split(',')[0] : request.ip;
  
  return ip;
});
