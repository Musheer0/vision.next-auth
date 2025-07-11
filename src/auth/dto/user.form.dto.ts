import { IsEmail, IsString, Max, MaxLength, Min, MinLength } from "class-validator";

export class UserFormDto {
    @IsEmail()
    email:string

    @IsString()
    @MinLength(6)
    @MaxLength(64)
    password:string
}