import { ObjectType } from '@nestjs/graphql';
import { User } from '../../user/entities/user.entity';
import { Token } from './token.entity';

@ObjectType()
export class Auth extends Token {
  user: User;
}