import {Module} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from 'src/prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './strategy/jwt.strategy';
import { VerificationToken } from './utils/create-verification-token';


@Module({
  providers: [AuthService,JwtStrategy,VerificationToken],
  controllers: [AuthController],
  imports:[PrismaModule,
    JwtModule.register({secret:process.env.AUTH_SECRET,signOptions:{expiresIn: '15d'}}),
    PassportModule
  ]
})
export class AuthModule {}
