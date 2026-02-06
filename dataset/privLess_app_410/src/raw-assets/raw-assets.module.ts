import { Module } from '@nestjs/common';
import { RawAssetsController } from './raw-assets.controller';
import { RawAssetsService } from './raw-assets.service';

@Module({
  imports: [],
  controllers: [RawAssetsController],
  providers: [RawAssetsService],
  exports: [RawAssetsService],
})
export class RawAssetsModule {}
