import { ConflictException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service.js';


@Injectable()
export class UsersService {
    constructor(private readonly prisma: PrismaService) { }

    async create(data: { email: string; password?: string | null; name: string }) {
        const existing = await this.prisma.user.findUnique({ where: { email: data.email } });
        if (existing) {
            throw new ConflictException('An account with this email already exists.');
        }
        return this.prisma.user.create({ data });
    }

    async findByEmail(email: string) {
        return this.prisma.user.findUnique({
            where: { email }
        })
    }
}
