import {Module} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from 'src/prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './strategy/jwt.strategy';
import { VerificationToken } from './utils/create-verification-token';
import { ClientsModule, Transport } from '@nestjs/microservices';


@Module({
  providers: [AuthService,JwtStrategy,VerificationToken],
  controllers: [AuthController],
  imports:[PrismaModule,
    JwtModule.register({secret:process.env.AUTH_SECRET,signOptions:{expiresIn: '15d'}}),
    PassportModule,
     ClientsModule.register([
      {
        name: 'EMAIL_SERVICE',
        transport: Transport.RMQ,
        options:{
          urls: ['amqp://localhost:5672'],
          queue: 'email-queue',
          queueOptions:{
            durable: false //TODO change to true in prod
          }
        }
      }
    ])
  ]
})
export class AuthModule {}
