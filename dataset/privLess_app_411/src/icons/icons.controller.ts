import { Controller, Get } from '@nestjs/common';

import { IconsService } from './icons.service';

@Controller('icons')
export class IconsController {
  constructor(private readonly appService: IconsService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }
}
