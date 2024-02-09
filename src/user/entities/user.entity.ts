import 'reflect-metadata';
import {
  ObjectType,
  registerEnumType,
  HideField,
  Field,
} from '@nestjs/graphql';
import { IsEmail } from 'class-validator';
import { BaseEntity } from 'src/common/entites/base.entity';

export enum Role {
  ADMIN = 'ADMIN',
  USER = 'USER'
}

registerEnumType(Role, {
  name: 'Role',
  description: 'User role',
});

@ObjectType()
export class User extends BaseEntity {
  @Field()
  @IsEmail()
  email: string;

  @Field()
  firstname: string;

  @Field()
  lastname: string;

  @Field(() => Role)
  role: Role;

  @Field()
  password: string;

  @Field()
  isVerified: boolean;
}
