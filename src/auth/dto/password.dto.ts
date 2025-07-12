import { IsString, MaxLength, MinLength } from "class-validator";
import { UserFormDto } from "./user.form.dto";

export class PasswordDto  {
    @IsString()
    @MinLength(6)
    @MaxLength(64)
    password:string

    @IsString()
    @MinLength(6)
    @MaxLength(6)
    code:string
}