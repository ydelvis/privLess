import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';

import { SubcriptionModule } from './subcription/subcription.module';
import { PaymentModule } from './payment/payment.module';
@Module({
  imports: [SubcriptionModule, PaymentModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
