import { Injectable } from '@nestjs/common';
import {generate} from 'otp-generator';
import { PrismaService } from 'src/prisma/prisma.service';
import { getFutureMinute } from '.';
@Injectable()
export class VerificationToken {
        constructor( private prisma:PrismaService){
    };
    async generateToken (ip:string, agent:string,id:string,session?:string){
        
        const opt= generate(6)
       const token = await this.prisma.verification_Token.create({
        data:{
            user_id:id,
            code:opt,
            ip,
            userAgent:agent,
            expiresAt: getFutureMinute(30),
            session_id:session
        }
       });
       return token;


    }

}