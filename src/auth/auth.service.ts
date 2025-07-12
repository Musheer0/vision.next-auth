import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { UserFormDto } from './dto/user.form.dto';
import {hash, verify} from 'argon2'
import { VerificationToken } from './utils/create-verification-token';
import { getFutureDate } from './utils';
import { CodeDto } from './dto/id.dto';
import { JwtService } from '@nestjs/jwt';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import base64url from 'base64url';
import crypto from 'crypto';
import { PasswordDto } from './dto/password.dto';
import { ClientProxy } from '@nestjs/microservices';
@Injectable()
export class AuthService {
    constructor(
        private prisma:PrismaService,
        private verificationToken:VerificationToken,
        private jwtService:JwtService,
        @Inject(CACHE_MANAGER) private cacheManager:Cache,
        @Inject('EMAIL_SERVICE') private client:ClientProxy
    ){}
    async signUp(data:UserFormDto, ip:string, user_agent:string){
        const {email,password} = data;
        const isExistingUser = await this.prisma.user.findUnique({where:{email}});
        if(isExistingUser) throw new ConflictException("user already exits");
        if(!ip || !user_agent) throw new BadRequestException("missing data");
        const  hashed_password = await hash(password,{secret:Buffer.from(process.env.AUTH_SECRET!)});
        const new_user = await this.prisma.user.create({
            data:{
                email,
                password:hashed_password
            },
            select:{
                email:true,
                id:true,
                isEmailVerified:true
            }
        });
         const session = await this.prisma.session.create({
            data:{
                user_id: new_user.id,
                expiresAt: getFutureDate(7),
                userAgent:user_agent,
                ip
            }
        });
        const veirfication_token = await this.verificationToken.generateToken(ip, user_agent, new_user.id,session.id);
        this.client.emit('verify.email',{code:veirfication_token.code, email})
        const token = {
           email:new_user.email,
            token:session.id,
            isVerified:new_user.isEmailVerified,
            id:new_user.id

        }
        const jwt_token  = await this.jwtService.sign(token,{  expiresIn: '7d',})
        return {
            success:true,
            message:'please verify your email',
            token:jwt_token
        }
        
    }
    async VerifyEmail(data:CodeDto,userId:string,id:string){
        const {code} = data;
        const verification_token = await this.prisma.verification_Token.findFirst({
            where:{
                id,
                user_id:userId,
            }
        });

        if(!verification_token || verification_token.code!==code) throw new NotFoundException("token not found");
        if(new Date(verification_token.expiresAt)<new Date()){
                    await this.prisma.verification_Token.delete({where:{id}});
            throw new BadRequestException("token expired");
        }
       await this.prisma.user.update({
            where:{
                id:verification_token.user_id
            },
            data:{
                isEmailVerified:new Date()
            },
                   select:{
                email:true,
                id:true,
                isEmailVerified:true
            }
        });
        if(verification_token.session_id) {
             await this.prisma.session.delete({
            where:{
                id:verification_token.session_id,
                user_id:userId
            },
        });
        }
        await this.prisma.verification_Token.delete({where:{id}});
        return {success:true}
       
    }
    async signIn(data:UserFormDto, ip:string, user_agent:string){
        const {email,password} = data;
        const user = await this.prisma.user.findUnique({where:{email},   
                select:{
                email:true,
                id:true,
                isEmailVerified:true,
                password:true
            }});
        if(!user) throw new NotFoundException("Invalid creadentials");
        if(!ip || !user_agent) throw new BadRequestException("missing data");
        const isCorrectPasswrd = await verify(user.password,password,{secret:Buffer.from(process.env.AUTH_SECRET!)});
        if(!isCorrectPasswrd) throw new NotFoundException("Invalid creadentials");
         const session = await this.prisma.session.create({
            data:{
                user_id: user.id,
                expiresAt: getFutureDate(user.isEmailVerified ? 15: 4),
                userAgent:user_agent,
                ip
            }
        });
        const token = {
           email:user.email,
            token:session.id,
            isVerified:user.isEmailVerified,
            id:user.id

        }
        const jwt_token  = await this.jwtService.sign(token,{  expiresIn: user.isEmailVerified?'15d' :'4d',})
        return {
            success:true,
            message:user.isEmailVerified ?'login success':'please verify your email',
            token:jwt_token
        }
        
    }
    async VerifyToken(token:string){
        const cahceSession = await this.cacheManager.get(`sess:${token}`);
        if(cahceSession) {
            return {session: cahceSession}
        }
        const session = await this.prisma.session.update({
            where:{
                id:token,
                expiresAt: {gt: new Date()}
            },
            data:{
                LastAccess :new Date()
            },
            select:{
                id:true,
                expiresAt:true,
                user: {
                    select:{
                        id:true,
                        email:true,
                        isEmailVerified:true,
                        createdAt:true
                    }
                },
            }
        });
        if(!session) throw new NotFoundException("invalid token");
        await this.cacheManager.set(`sess:${token}`,session,6000)
        return {session}
    }
    async Logout(token:string){
 const cahceSession = await this.cacheManager.get(`sess:${token}`);
        if(cahceSession) {
            await this.cacheManager.del(`sess:${token}`)
        }
        const session = await this.prisma.session.delete({
            where:{
                id:token,
            }
        });
        if(!session) throw new NotFoundException("invalid token");
        return {success:true}
    }
   async GenerateResetPasswordLink(email: string, ip: string, agent: string) {
    const user = await this.prisma.user.findUnique({
        where: { email },
        select: {
            id: true,
            isEmailVerified: true,
            email: true
        }
    });

    if (!user) throw new NotFoundException("user not found");

    if (!user.isEmailVerified) {
        const token = await this.verificationToken.generateToken(ip, agent, user.id);
        this.client.emit('verify.email', { code: token.code, email: user.email });

        throw new BadRequestException("Email not verified. Verification email sent.");
    }

    const resetToken = await this.verificationToken.generateToken(ip, agent, user.id);
    if(!resetToken) throw new BadRequestException("error creating token")
    this.client.emit('verify.password', { code: resetToken.code, email: user.email });

    const encoded = base64url.encode(resetToken.id);
    return { token: encoded };
}

   async resetPassword(token: string, data: PasswordDto, agent: string) {
    const id = base64url.decode(token);

    const verification_token = await this.prisma.verification_Token.findFirst({
        where: {
            id,
            userAgent: agent,
            code: data.code
        }
    });

    if (!verification_token) throw new NotFoundException("Invalid or expired reset token");

    const user = await this.prisma.user.findUnique({
        where: { id: verification_token.user_id },
        select: { isEmailVerified: true, email: true }
    });

    if (!user) throw new NotFoundException("User not found");

    if (!user.isEmailVerified) {
        const reverify = await this.verificationToken.generateToken("0.0.0.0", agent, verification_token.user_id); // optional IP fallback
        this.client.emit("verify.email", { code: reverify.code, email: user.email });

        throw new BadRequestException("Email not verified. Verification email sent.");
    }

    const hashed_password = await hash(data.password, { secret: Buffer.from(process.env.AUTH_SECRET!) });

    await this.prisma.user.update({
        where: { id: verification_token.user_id },
        data: { password: hashed_password }
    });

    this.client.emit('notify.password', user.email);

    await this.prisma.verification_Token.delete({ where: { id } });

    await this.prisma.session.deleteMany({
        where: {
            user_id: verification_token.user_id
        }
    });

    return { success: true };
}

}
