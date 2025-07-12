import { IsEmail, IsString, MaxLength, MinLength } from "class-validator";
import { UserFormDto } from "./user.form.dto";

export class EmailDto  {
    @IsEmail()
    email:string
}