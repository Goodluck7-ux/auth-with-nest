import { Body, Controller, Get, HttpCode, Post, Req, Res, UnauthorizedException, UseGuards, Query } from '@nestjs/common';
import { AuthService } from './auth.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import { Roles } from './decorators/roles.decorator.js';
import { RolesGuard } from './guards/roles.guard.js';
import type { Request, Response } from 'express';
import { randomBytes } from 'crypto';


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
    async logout(
        @Req() request: Request,
        @Res({ passthrough: true }) response: Response,
    ) {
        const refreshToken = request.cookies?.refresh_token;
        response.clearCookie('refresh_token', { path: '/auth/refresh' });
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


    @Get('google')
    googleAuth(@Res() response: Response) {
        const state = randomBytes(16).toString('hex');

        response.cookie('oauth_state', state, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 5 * 60 * 1000,
        });

        const params = new URLSearchParams({
            client_id: process.env.GOOGLE_CLIENT_ID!,
            redirect_uri: process.env.GOOGLE_CALLBACK_URL!,
            response_type: 'code',
            scope: 'openid email profile',
            state,
            prompt: 'select_account',
        });

        response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
    }

    @Get('google/callback')
    async googleCallback(
        @Query('code') code: string,
        @Query('state') state: string,
        @Req() request: Request,
        @Res() response: Response,
    ) {
        const savedState = request.cookies?.oauth_state;
        response.clearCookie('oauth_state');

        if (!state || state !== savedState) {
            throw new UnauthorizedException('Invalid OAuth state — possible CSRF attempt');
        }

        const result = await this.authService.googleLogin(code);

        response.cookie('refresh_token', result.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/auth/refresh',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        response.redirect(`${process.env.FRONTEND_URL}/oauth/callback?accessToken=${result.accessToken}`);
    }
}
