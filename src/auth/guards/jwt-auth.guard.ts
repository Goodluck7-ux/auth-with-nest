import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";


@Injectable()
export class JwtAuthGuard implements CanActivate {
    constructor(private readonly jwtService: JwtService) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest()
        const token = this.extractTokenFromHeader(request)

        if (!token) {
            throw new UnauthorizedException('No token provided')

        }

        try {
            const payload = await this.jwtService.verifyAsync(token)
            request.user = { userId: payload.sub, email: payload.email, role: payload.role }
        }
        catch {
            throw new UnauthorizedException('Invalid or expired token')
        }
        return true
    }

    private extractTokenFromHeader(request: any): string | undefined {
        const authHeader: string | undefined = request.headers.authorization;
        if (!authHeader) return undefined;

        const [type, token] = authHeader.trim().split(' ');
        return type === 'Bearer' && token ? token.trim() : undefined;
    }
}