import {
    Body,
    Controller,
    forwardRef,
    Get,
    Inject,
    Param,
    Patch,
    Post,
    Put,
} from '@nestjs/common';

import { PaymentService } from './payment.service';

@Controller("payment")
export class PaymentController {
    constructor(
        @Inject(forwardRef(() => PaymentService))
        private readonly paymentService: PaymentService
    ) { }


}