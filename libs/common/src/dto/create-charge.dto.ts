// import { Type } from 'class-transformer';
import {
  // IsDefined,
  // IsNotEmpty,
  // IsNotEmptyObject,
  IsNumber,
  // ValidateNested,
} from 'class-validator';
// import { CardDto } from './card.dto';

export class CreateChargeDto {
  // @IsDefined()
  // @IsNotEmptyObject()
  // @ValidateNested()
  // @Type(() => CardDto)
  // card: CardDto;

  // @IsDefined()
  // @IsNotEmpty()
  // cardToken: string;

  @IsNumber()
  amount: number;
}
