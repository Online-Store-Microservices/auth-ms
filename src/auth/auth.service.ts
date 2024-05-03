import { HttpStatus, Inject, Injectable } from '@nestjs/common';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';
import * as bcrypt from 'bcrypt';
import { NATS_SERVICE, envs } from 'src/config';
import { LoginDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { IJwtPayload } from './interfaces';


@Injectable()
export class AuthService {

    constructor(
        @Inject(NATS_SERVICE) private readonly client: ClientProxy,
        private jwtService: JwtService
    ){}

    async signJWT(payload: IJwtPayload) {
        return this.jwtService.sign(payload);
    }

    async login(loginDto: LoginDto): Promise<any> {
        try {
            const user =  await firstValueFrom<IJwtPayload & { password: string }>(
                this.client.send('find_user_by_email',{email: loginDto.email})
            );
                

            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password not valid',
                });
            }

            const isPasswordValid = bcrypt.compareSync(loginDto.password, user.password);

            if (!isPasswordValid) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password not valid',
                });
            }
        
            const { password: __, ...rest } = user;

            return {
              user: rest,
              token: await this.signJWT(rest),
            };
        } catch (error) {
            throw new RpcException({ 
                message: error.message, 
                status: error?.error?.status??HttpStatus.INTERNAL_SERVER_ERROR 
            });
        }
    }


    async verifyToken(token: string) {
        try {
          
          const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
            secret: envs.jwtSecret,
          });
    
          return {
            user: user,
            token: await this.signJWT(user),
          }
    
        } catch (error) {
          throw new RpcException({
            status: HttpStatus.UNAUTHORIZED,
            message: 'Invalid token'
          })
        }
    
    }
}
