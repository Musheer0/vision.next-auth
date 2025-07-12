import { Controller, Delete, Get, Param, Patch, UseGuards } from '@nestjs/common';
import { Body, Ip, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserFormDto } from './dto/user.form.dto';
import { UserAgent } from './decorators/user-agent.decorator';
import { IdDto } from './dto/id.dto';
import { JwtAuthGuard } from './guards/auth.guard';
import { User } from './decorators/user.decorator';
import { EmailDto } from './dto/email.dto';
import { PasswordDto } from './dto/password.dto';

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
  @UseGuards(JwtAuthGuard)
  @Get('/verify/token')
  verifyToken(@User() user){
    return this.authService.VerifyToken(user.token)
  }
  @UseGuards(JwtAuthGuard)
  @Delete('/logout')
  logout (@User() user){
    console.log(user)
    return this.authService.Logout(user.token)
  }
  @Post('/generate/reset-password')
  generateResetPassword(@Body() body :EmailDto, @Ip() ip , @UserAgent() agent){
    return this.authService.GenerateResetPasswordLink(body.email,ip,agent);
  } 
  @Patch('/reset/password/:id')
  resetPassword(@Body() body:PasswordDto,@UserAgent() agent, @Param('id') id:string){
    return this.authService.resetPassword(id, body,agent)
  }
}
