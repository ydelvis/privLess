import { Body, Controller, Get, Param, Post } from '@nestjs/common';

import {
  RawAsset,
  RawAssetRegisterRequest,
  RawAssetRegisterResponse,
} from '@bridged.xyz/client-sdk/lib/assets';
import { RawAssetsService } from './raw-assets.service';

@Controller('raw-assets')
export class RawAssetsController {
  constructor(private readonly rawAssetsService: RawAssetsService) {}

  @Post('/')
  async postRawAsset(
    @Body() req: RawAssetRegisterRequest
  ): Promise<RawAssetRegisterResponse> {
    const asset = await this.rawAssetsService.createRawAsset(req);

    return {
      success: true,
      data: asset,
      message: 'asset registered successfully',
    };
  }

  @Get(':id')
  async getRawAsset(@Param() p: { id: string }): Promise<RawAsset> {
    const id = p.id;
    const asset = await this.rawAssetsService.fetchRawAsset(id);
    return asset;
  }
}
