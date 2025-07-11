import { Controller, UseGuards } from '@nestjs/common';
import { Body, Ip, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserFormDto } from './dto/user.form.dto';
import { UserAgent } from './decorators/user-agent.decorator';
import { IdDto } from './dto/id.dto';
import { JwtAuthGuard } from './guards/auth.guard';
import { User } from './decorators/user.decorator';

@Controller('auth')
export class AuthController {
     constructor(private readonly authService:AuthService){}
  @Post('/sign-up')
  signUp(@Body() body:UserFormDto, @Ip() ip , @UserAgent() agent){
    return this.authService.signUp(body, ip, agent);
  }
  @Post('/sign-in')
  signIn(@Body() body:UserFormDto, @Ip() ip , @UserAgent() agent){
    return this.authService.signIn(body, ip, agent);
  }
  @UseGuards(JwtAuthGuard)
  @Post('/verify/email')
  verifyEmail(@Body() body:IdDto, @Ip() ip , @UserAgent() agent,@User() user){
    return this.authService.VerifyEmail(body,agent,ip, user.id);
  }
}
