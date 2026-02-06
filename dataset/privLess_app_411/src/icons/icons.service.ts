import { Injectable } from '@nestjs/common';

@Injectable()
export class IconsService {
  getHello(): string {
    return 'Hello World!';
  }
}
