import { Injectable } from "@nestjs/common";
import * as AWS from "aws-sdk";
import { DocumentClient } from "aws-sdk/lib/dynamodb/document_client";

import { UrlShortenResult } from "@bridged.xyz/client-sdk/dist/url/types";
import { buildShortUrl, generateHash } from "./utils";

const dynamoDb = new AWS.DynamoDB.DocumentClient();

interface TBL_URL_SPEC {
  id: string;
  host: string;
  target: string;
}

@Injectable()
export class AppService {
  getHello(): string {
    return "Welcome to Grida hosting service. Learn more at https://github.com/gridaco/base/";
  }

  async getRedirect(id: string): Promise<string> {
    const param: DocumentClient.GetItemInput = {
      TableName: process.env.DYNAMODB_TABLE,
      Key: {
        id: id,
      },
    };
    const record = await dynamoDb.get(param).promise();
    const data = record.Item as TBL_URL_SPEC;
    const origin = data.target;
    return origin;
  }

  async createRecord(url: string): Promise<UrlShortenResult> {
    const hash = generateHash();
    const data: TBL_URL_SPEC = {
      id: hash,
      host: process.env.HOST,
      target: url,
    };
    const params: DocumentClient.PutItemInput = {
      TableName: process.env.DYNAMODB_TABLE,
      Item: data,
    };
    await dynamoDb.put(params).promise();
    const newUrl = buildShortUrl(data.id, data.host);
    const result: UrlShortenResult = {
      id: data.id,
      url: newUrl,
      origin: url,
      host: data.host,
    };
    return result;
  }
}
