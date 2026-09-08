import { Injectable, ConflictException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service.js';
import { JwtService } from '@nestjs/jwt';
import { randomBytes, createHash } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service.js';

const SALT_ROUNDS = 10;
@Injectable()
export class AuthService {
    constructor(private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
        private readonly prismaService: PrismaService

    ) { }

    async register(data: { email: string; password: string; name: string }) {
        const existingUser = await this.usersService.findByEmail(data.email);
        if (existingUser) {
            throw new ConflictException('User with this email already exists');
        }

        const hashedPassword = await bcrypt.hash(data.password, SALT_ROUNDS);
        const user = await this.usersService.create({ ...data, password: hashedPassword });
        const { password, ...safeUser } = user;

        return { status: 'success', message: 'User registered successfully', user: safeUser };
    }

    async login(data: { email: string; password: string }) {
        const user = await this.usersService.findByEmail(data.email);

        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const passwordsMatch = await bcrypt.compare(data.password, user.password);
        if (!passwordsMatch) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const payload = { email: user.email, sub: user.id, role: user.role };
        const accessToken = await this.jwtService.signAsync(payload);
        // return { accessToken,}

        const { password, ...safeUser } = user

        const { rawToken, tokenHash } = this.generateRefreshToken();

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);

        await this.prismaService.session.create({
            data: {
                userId: user.id,
                refreshToken: tokenHash,
                expiresAt,
            },
        });
        return { status: 'success', message: 'Login successful', user: safeUser, accessToken, refreshToken: rawToken };


    }

    async refresh(rawRefreshToken: string) {
        if (!rawRefreshToken) {
            throw new UnauthorizedException('Refresh token is required');
        }

        const tokenHash = createHash('sha256')
            .update(rawRefreshToken)
            .digest('hex');

        const session = await this.prismaService.session.findUnique({
            where: {
                refreshToken: tokenHash,
            },
            include: {
                user: true,
            },
        });

        if (!session) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        if (session.revokedAt) {
            throw new UnauthorizedException('Refresh token has been revoked');
        }

        if (session.expiresAt <= new Date()) {
            throw new UnauthorizedException('Refresh token expired');
        }

        // Revoke the old refresh token
        await this.prismaService.session.update({
            where: {
                id: session.id,
            },
            data: {
                revokedAt: new Date(),
            },
        });

        // Create a new refresh token
        const { rawToken: newRawToken, tokenHash: newTokenHash } =
            this.generateRefreshToken();

        const newExpiresAt = new Date();
        newExpiresAt.setDate(newExpiresAt.getDate() + 7);

        await this.prismaService.session.create({
            data: {
                userId: session.userId,
                refreshToken: newTokenHash,
                expiresAt: newExpiresAt,
            },
        });

        // Create a new access token
        const payload = {
            email: session.user.email,
            sub: session.user.id,
            role: session.user.role,
        };

        const accessToken = await this.jwtService.signAsync(payload);

        return {
            accessToken,
            refreshToken: newRawToken,
        };
    }

    private generateRefreshToken() {
        const rawToken = randomBytes(64).toString('hex');

        const tokenHash = createHash('sha256')
            .update(rawToken)
            .digest('hex');

        return { rawToken, tokenHash };
    }

    async logout(refreshTokenValue: string) {
        const tokenHash = createHash('sha256')
            .update(refreshTokenValue)
            .digest('hex');

        await this.prismaService.session.updateMany({
            where: { refreshToken: tokenHash, revokedAt: null },
            data: { revokedAt: new Date() },
        });

        return { status: 'success', message: 'Logged out successfully' };
    }


}
