import { Module } from '@nestjs/common';

import { RawAssetsService } from '../raw-assets/raw-assets.service';
import { VariantAssetsController } from './variant-assets.controller';
import { VariantAssetsService } from './variant-assets.service';

@Module({
  imports: [RawAssetsService],
  controllers: [VariantAssetsController],
  providers: [VariantAssetsService, RawAssetsService],
})
export class VariantAssetsModule {}
