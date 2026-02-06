import { Injectable } from '@nestjs/common';
import { nanoid } from 'nanoid';

import {
  RawAsset,
  RawAssetRegisterRequest,
  VariantAddRequest,
  NestedAssetPutRequest,
  VariantAsset,
  VariantAssetRegisterRequest,
  VariantPutRequest,
  VariantUpdateRequest,
} from '@bridged.xyz/client-sdk/lib/assets';
import { RawAssetsService } from '../raw-assets/raw-assets.service';
import { VariantAssetTable, VariantAssetModel } from '../app.entity';

@Injectable()
export class VariantAssetsService {
  constructor(private readonly rawAssetsService: RawAssetsService) {}

  async fetchVariantAsset(id: string): Promise<VariantAsset> {
    console.log('fetching variant asset with id', id);
    const variantAsset = await VariantAssetModel.get(id);
    // as VariantAssetTable

    const assetsInVariantAsset = variantAsset.assets;
    console.log('assetsInVariantAsset', assetsInVariantAsset);

    // get assets
    const rawAssetIds = Object.keys(assetsInVariantAsset).map(function(key) {
      return assetsInVariantAsset[key];
    });
    const rawAssets = await this.rawAssetsService.fetchRawAssets(rawAssetIds);

    // convert `variant name: asset id` map to `variant name: asset`
    const assetMap = assetsToMap(assetsInVariantAsset, rawAssets);

    // transform record to variant asset
    const finalVariantAsset: VariantAsset = {
      id: variantAsset.id,
      projectId: variantAsset.projectId,
      key: variantAsset.key,
      description: variantAsset.description,
      name: variantAsset.name,
      type: variantAsset.type,
      // TODO fix this layer on. - https://github.com/dynamoose/dynamoose/issues/1073
      // tags: variantAsset.tags,
      assets: assetMap,
    };

    return finalVariantAsset;
  }

  async registerVariantAsset(
    projectId: string,
    request: VariantAssetRegisterRequest
  ): Promise<any> {
    const id = nanoid();

    // register assets first
    console.log('request.initialAssets', request.initialAssets);
    const initialAssetKeys = Object.keys(request.initialAssets);
    const registeredRawAssets: Array<RawAsset> = [];
    for (const key of initialAssetKeys) {
      const minimizedAssetRegisterRequest: NestedAssetPutRequest =
        request.initialAssets[key];
      const fullAssetRegiisterRequest: RawAssetRegisterRequest = {
        name: minimizedAssetRegisterRequest.name,
        value: minimizedAssetRegisterRequest.value,
        tags: minimizedAssetRegisterRequest.tags,
        key: request.key,
        type: request.type,
      };

      // asset created
      const asset = await this.rawAssetsService.createRawAsset(
        fullAssetRegiisterRequest
      );
      registeredRawAssets.push(asset);
    }

    // make variant name : asset id map
    const assetIdMap = new Map<string, string>();
    const varaintNames = Object.keys(request.initialAssets);
    for (let i = 0; i < varaintNames.length; i++) {
      const variantName = varaintNames[i];
      const variantRawAsset = registeredRawAssets[i];
      assetIdMap[variantName] = variantRawAsset.id;
    }

    const record = new VariantAssetModel(<VariantAssetTable>{
      id: id,
      key: request.key,
      projectId: projectId,
      name: request.name,
      type: request.type,
      // TODO fix this layer on. - https://github.com/dynamoose/dynamoose/issues/1073
      // tags: variantAsset.tags,
      description: request.description,
      assets: { ...assetIdMap },
    });
    const created = await record.save();

    const builtAssetMap = assetsToMap(assetIdMap, registeredRawAssets);

    return {
      ...created,
      assets: builtAssetMap,
    };
  }

  async updateVariant(request: VariantUpdateRequest) {
    console.log('update variant with request', request);
    const id = request.variantAssetId;
    const variantName = request.variant;
    const variantAsset = ((await VariantAssetModel.get(
      id
    )) as any) as VariantAssetTable;

    const variantId = variantAsset.assets[variantName];
    console.log(
      'updating raw asset linked to this variant with raw asset id of',
      variantId
    );
    await this.rawAssetsService.updateRawAsset(variantId, {
      id: variantId,
      ...request.asset,
    });

    return await this.fetchVariantAsset(id);
  }

  async addVariant(request: VariantAddRequest) {
    console.log('add variant with request', request);
    const id = request.variantAssetId;
    const variantName = request.variant;
    const variantAsset = ((await VariantAssetModel.get(
      id
    )) as any) as VariantAssetTable;
    console.log(
      'permorming add variant request to existing variat asset',
      variantAsset
    );
    const newRawAsset = await this.rawAssetsService.createRawAsset({
      type: variantAsset.type,
      ...request.asset,
    });

    const updatedAssetsMap: Map<string, string> = variantAsset.assets;
    // add new raw asset to variants
    updatedAssetsMap[variantName] = newRawAsset.id;

    // update with added raw asset
    await VariantAssetModel.update(
      {
        id: id,
      },
      {
        assets: updatedAssetsMap,
      }
    );

    return await this.fetchVariantAsset(id);
  }

  async putVariant(request: VariantPutRequest) {
    console.log('put variant with request', request);
    const variant = request.variant;
    const id = request.variantAssetId;
    const variantAsset = await this.fetchVariantAsset(id);
    const exists =
      Object.keys(variantAsset.assets).find(v => v == variant) !== undefined;
    if (exists) {
      console.log(
        'handling put request. since data exists already, performing "update"'
      );
      return await this.updateVariant(request);
    } else {
      console.log(
        'handling put request. since data is fresh and new, performing "add"'
      );
      return await this.addVariant({
        variant: request.variant,
        variantAssetId: request.variantAssetId,
        asset: {
          value: request.asset.value,
          tags: request.asset.tags,
          name: request.asset.name,
        },
      });
    }
  }

  async fetchVariantAssetsInProject(
    projectId: string
  ): Promise<Array<VariantAsset>> {
    const PROJECT_INDEX_NAME = 'projectIndex';
    const variantAssetRecords = await VariantAssetModel.query('projectId')
      .eq(projectId)
      .using(PROJECT_INDEX_NAME)
      .exec();

    const requests: Array<Promise<VariantAsset>> = [];
    for (const variantAssetRecord of variantAssetRecords) {
      const variantAssetRequest = this.fetchVariantAsset(variantAssetRecord.id);
      requests.push(variantAssetRequest);
    }
    const results = Promise.all(requests);
    return results;
  }
}

/**
 * converts `variant name: asset id` map to `variant name: asset`
 * @param assetMap
 * @param assets
 */
function assetsToMap(
  assetMap: Map<string, string>,
  assets: RawAsset[]
): Map<string, RawAsset> {
  const result = new Map<string, RawAsset>();
  const assetKeys = Object.keys(assetMap);
  for (const key of assetKeys) {
    const assetId = assetMap[key];
    const asset = assets.find(a => a.id == assetId);

    result[key] = asset;
  }

  return result;
}
