import { Controller, Inject, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { NATS_SERVICE } from 'src/config';
import { ClientProxy, MessagePattern, Payload } from '@nestjs/microservices';
import { LoginDto } from './dto';

@Controller()
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    @Inject(NATS_SERVICE) private readonly client: ClientProxy
  ) {}

  
  @MessagePattern('auth_login')
  login(@Payload() loginDto: LoginDto){
    return this.authService.login(loginDto);
  }

  @MessagePattern('verify_token')
  verifyToken(@Payload() token: string){
    return this.authService.verifyToken(token);
  }
}
