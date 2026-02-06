import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Welcome to bridged hosting service. Learn more at https://github.com/bridgedxyz/services/';
  }
}
