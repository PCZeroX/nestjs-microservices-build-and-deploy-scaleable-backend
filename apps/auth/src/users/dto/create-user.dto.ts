import {
  IsEmail,
  // IsArray,
  // IsNotEmpty,
  // IsOptional,
  // IsString,
  IsStrongPassword,
} from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsStrongPassword()
  password: string;

  // @IsOptional()
  // @IsArray()
  // @IsString({ each: true })
  // @IsNotEmpty({ each: true })
  // roles?: string[];
}
