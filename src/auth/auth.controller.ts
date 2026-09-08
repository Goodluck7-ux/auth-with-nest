import { Body, Controller, Get, HttpCode, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import { Roles } from './decorators/roles.decorator.js';
import { RolesGuard } from './guards/roles.guard.js';
import type { Request, Response } from 'express';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('register')
    async register(@Body() data: RegisterDto) {
        return this.authService.register(data);
    }

    @Post('login')
    @HttpCode(200)
    async login(
        @Body() data: LoginDto,
        @Res({ passthrough: true }) response: Response,
    ) {
        const result = await this.authService.login(data);

        response.cookie('refresh_token', result.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/auth/refresh',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        const { refreshToken: _, ...safeResult } = result;

        return safeResult;
    }

    @Post('refresh')
    @HttpCode(200)
    async refresh(
        @Req() request: Request,
        @Res({ passthrough: true }) response: Response,
    ) {
        const refreshToken = request.cookies?.refresh_token;

        const result = await this.authService.refresh(refreshToken);

        response.cookie('refresh_token', result.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/auth/refresh',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        const { refreshToken: _, ...safeResult } = result;

        return safeResult;
    }


    @Post('logout')
    @HttpCode(200)
    async logout(@Body('refreshToken') refreshToken: string) {
        return this.authService.logout(refreshToken);
    }

    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me')
    getMe(@Req() request: any) {
        return request.user
    }

    @UseGuards(JwtAuthGuard)
    @Roles('ADMIN')
    @Get('admin-only')
    adminOnly(@Req() request: any) {
        return { message: `Welcome, admin ${request.user.email}!` };
    }
}
