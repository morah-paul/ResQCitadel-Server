import { Module } from '@nestjs/common';
import { UsersResolver } from './user.resolver';
import { UsersService } from './user.service';
import { PasswordService } from '../auth/password.service';

@Module({
  imports: [],
  providers: [UsersResolver, UsersService, PasswordService],
})
export class UsersModule {}