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

import {
  NestedAssetPutRequest,
  VariantAssetRegisterRequest,
} from '@bridged.xyz/client-sdk/lib/assets';
import { VariantAssetsService } from './variant-assets.service';

@Controller('variant-assets')
export class VariantAssetsController {
  constructor(
    @Inject(forwardRef(() => VariantAssetsService))
    private readonly variantAssetsService: VariantAssetsService
  ) {}

  @Post('/')
  async postCreateVariantAsset(
    @Body() req: VariantAssetRegisterRequest
  ): Promise<any> {
    const projectId = 'temp';
    return await this.variantAssetsService.registerVariantAsset(projectId, req);
  }

  @Get('/:id')
  async getVariantAsset(@Param() p: { id: string }): Promise<any> {
    const id = p.id;
    return await this.variantAssetsService.fetchVariantAsset(id);
  }

  /**
   * get all variant assets in the project. project id provided in header
   */
  @Get('/')
  async getVariantAssets() {
    console.log('getting all variant assets in project');
    const projectId = 'demo';
    return this.variantAssetsService.fetchVariantAssetsInProject(projectId);
  }

  @Patch('/:id/variants/:variant')
  async updateVariant(
    @Param() p: VariantAccessorParam,
    @Body() body: NestedAssetPutRequest
  ): Promise<any> {
    const updatedVariantAsset = await this.variantAssetsService.updateVariant({
      variantAssetId: p.id,
      variant: p.variant,
      asset: body,
    });

    return updatedVariantAsset;
  }

  @Put('/:id/variants/:variant')
  async putVariant(
    @Param() p: VariantAccessorParam,
    @Body() body: NestedAssetPutRequest
  ) {
    return await this.variantAssetsService.putVariant({
      variantAssetId: p.id,
      variant: p.variant,
      asset: body,
    });
  }

  @Post('/:id/variants/:variant')
  async addVariant(
    @Param() p: VariantAccessorParam,
    @Body() body: NestedAssetPutRequest
  ) {
    return await this.variantAssetsService.addVariant({
      variantAssetId: p.id,
      variant: p.variant,
      asset: body,
    });
  }
}

/**
 * an indicator to locate variant (raw asset) from variant asset. via id and variant key
 */
interface VariantAccessorParam {
  id: string;
  variant: string;
}
