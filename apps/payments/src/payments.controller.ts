import { MessagePattern, Payload } from '@nestjs/microservices';
import { Controller, UsePipes, ValidationPipe } from '@nestjs/common';

import { PaymentsService } from './payments.service';

import { CreateChargeDto } from '@app/common';

@Controller()
export class PaymentsController {
  constructor(private readonly paymentsService: PaymentsService) {}

  @MessagePattern('create_charge')
  @UsePipes(new ValidationPipe())
  async createCharge(
    @Payload() data: CreateChargeDto,
    // @Payload() data: PaymentsCreateChargeDto,
  ) {
    return this.paymentsService.createCharge(data);
  }
}
