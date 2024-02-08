import { InputType, Field } from '@nestjs/graphql';

@InputType()
export class UpdateUserInput {
  @Field()
  firstname: string;
  @Field()
  lastname: string;
}