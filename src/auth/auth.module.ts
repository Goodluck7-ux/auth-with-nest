import { Module } from '@nestjs/common';
import { AuthService } from './auth.service.js';
import { AuthController } from './auth.controller.js';
import { UsersModule } from '../users/users.module.js';
import { JwtModule } from '@nestjs/jwt';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import { RolesGuard } from './guards/roles.guard.js';
import { PrismaModule } from '../prisma/prisma.module.js';

@Module({
  imports: [UsersModule, JwtModule.register({
    secret: process.env.JWT_SECRET,
    signOptions: { expiresIn: '20m' }
  }), PrismaModule],
  providers: [AuthService, JwtAuthGuard, RolesGuard],
  controllers: [AuthController]
})
export class AuthModule { }
