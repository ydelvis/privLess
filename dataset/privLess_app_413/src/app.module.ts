import { Module } from '@nestjs/common';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ResourceModule } from './resource/resource.module';
import { SiteModule } from './site/site.module';

@Module({
  imports: [ResourceModule, SiteModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
