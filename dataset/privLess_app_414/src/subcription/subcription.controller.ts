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

import { SubcriptionService } from './subcription.service';

@Controller("subcription")
export class SubcriptionController {
    constructor(
        @Inject(forwardRef(() => SubcriptionService))
        private readonly subcriptionService: SubcriptionService
    ) { }

    
}