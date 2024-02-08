import { InputType, Field } from '@nestjs/graphql';
import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

@InputType()
export class SignupInput {
  @Field()
  @IsEmail()
  email: string;

  @Field()
  @IsNotEmpty()
  firstname: string

  @Field()
  @IsNotEmpty()
  lastname: string;

  @Field()
  @IsNotEmpty()
  @MinLength(8)
  password: string;
}
