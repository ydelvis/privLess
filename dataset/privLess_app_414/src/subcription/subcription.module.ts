import { Module } from '@nestjs/common';

import { SubcriptionController } from './subcription.controller';
import { SubcriptionService } from './subcription.service';

@Module({
    imports: [SubcriptionService],
    controllers: [SubcriptionController],
    providers: [SubcriptionService]
})
export class SubcriptionModule {}