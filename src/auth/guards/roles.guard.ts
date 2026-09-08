import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private readonly reflector: Reflector) {}

    canActivate(context: ExecutionContext): boolean {
        const requiredRoles = this.reflector.getAllAndOverride<string[]>('roles', [
            context.getHandler(),
            context.getClass(),
        ]);

        if(!requiredRoles || requiredRoles.length === 0) {
            return true; // No roles required, allow access
        }

        const request = context.switchToHttp().getRequest();
        const user = request.user;

        return requiredRoles.includes(user?.role); // Check if user's role is in the required roles
    }
}
