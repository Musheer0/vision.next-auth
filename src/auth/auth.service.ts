import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { UserFormDto } from './dto/user.form.dto';
import {hash, verify} from 'argon2'
import { VerificationToken } from './utils/create-verification-token';
import { getFutureDate } from './utils';
import { IdDto } from './dto/id.dto';
import { JwtService } from '@nestjs/jwt';
@Injectable()
export class AuthService {
    constructor(private prisma:PrismaService,private verificationToken:VerificationToken,private jwtService:JwtService){}
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
       //TODO send email
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
    async VerifyEmail(data:IdDto,user_agent:string, ip:string,userId:string){
        const {id} = data;
        const verification_token = await this.prisma.verification_Token.findFirst({
            where:{
                id,
                userAgent:user_agent,
                user_id:userId
            }
        });
        if(!verification_token || !verification_token.session_id) throw new NotFoundException("token not found");
        if(new Date(verification_token.expiresAt)<new Date()){
            throw new BadRequestException("token expired")
        }
       const user =  await this.prisma.user.update({
            where:{
                id:verification_token.user_id
            },
            data:{
                isEmailVerified:new Date()
            }
        });
        const session = await this.prisma.session.update({
            where:{
                id:verification_token.session_id,
                user_id:userId
            },
            data:{
                user_id: verification_token.user_id,
                expiresAt: getFutureDate(15),
                userAgent:user_agent,
                ip
            }
        });
        await this.prisma.verification_Token.delete({where:{id}});
        const token = {
            email:user.email,
            token:session.id,
            isVerified:user.isEmailVerified,
            id:user.id
        };
        const jwt_token = await this.jwtService.sign(token)
        return {
            token: jwt_token,
            expiresAt:session.expiresAt,
            message:'user verified'
        }
    }
      async signIn(data:UserFormDto, ip:string, user_agent:string){
        const {email,password} = data;
        const user = await this.prisma.user.findUnique({where:{email}});
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
}
