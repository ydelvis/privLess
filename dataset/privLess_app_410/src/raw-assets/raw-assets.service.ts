import { Injectable } from '@nestjs/common';
import * as AWS from 'aws-sdk';
import { DocumentClient } from 'aws-sdk/lib/dynamodb/document_client';
import { nanoid } from 'nanoid';

import {
  RawAssetRegisterRequest,
  RawAsset,
  RawAssetUpdateRequest,
} from '@bridged.xyz/client-sdk/lib/assets';
import { RawAssetModel, RawAssetTable } from '../app.entity';

const dynamoDb = new AWS.DynamoDB.DocumentClient();

const TBL_RAW_ASSETS = process.env.DYNAMODB_TABLE_RAW_ASSETS;
@Injectable()
export class RawAssetsService {
  getHello(): string {
    return 'Welcome to bridged hosting service. Learn more at https://github.com/bridgedxyz/services/';
  }

  async createRawAsset(request: RawAssetRegisterRequest): Promise<RawAsset> {
    // TODO handle by types. -> if input contains image, then host image and make a asset record.
    // only text asset is supported at this point

    const id = nanoid();
    const body: DocumentClient.PutItemInput = {
      TableName: TBL_RAW_ASSETS,
      Item: {
        id: id,
        ...request,
      },
    };
    dynamoDb.put(body).promise();

    return {
      id: id,
      ...request,
    };
  }

  async fetchRawAsset(id: string): Promise<RawAsset> {
    const query: DocumentClient.GetItemInput = {
      TableName: TBL_RAW_ASSETS,
      Key: { id: id },
    };

    const itemRes = await dynamoDb.get(query).promise();
    const record: RawAsset = itemRes.Item as RawAsset;
    return record;
  }

  async fetchRawAssets(ids: string[]): Promise<Array<RawAsset>> {
    // TODO -> implement this via batch query for better performance
    const requests: Array<Promise<RawAsset>> = [];
    for (const id of ids) {
      requests.push(this.fetchRawAsset(id));
    }

    const results = await Promise.all(requests);
    return results;
  }

  async updateRawAsset(id: string, request: RawAssetUpdateRequest) {
    const update = <RawAssetTable>{
      // name: request.name,
      // type: request.type,
      value: request.value,
      // tags: request.tags
    };
    console.log(
      'updating raw asset with request',
      request,
      'the update value is..',
      update
    );
    const updated = await RawAssetModel.update({ id: id }, { $SET: update });
    console.log('updated raw asset', id, updated);
    return updated;
  }
}
