import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { NATS_SERVICE, envs } from 'src/config';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports:[
    ClientsModule.register([
      {
        name: NATS_SERVICE,
        transport: Transport.NATS,
        options:{
          servers: envs.natsServers
        }
      }
    ]),
    JwtModule.register({
      global: true,
      secret: envs.jwtSecret,
      signOptions: { expiresIn: '2h' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
