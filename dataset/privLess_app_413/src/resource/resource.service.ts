import { Injectable } from '@nestjs/common';
import { nanoid } from 'nanoid';
import S3 from 'aws-sdk/clients/s3';

import { FileHostingResult } from '@bridged.xyz/client-sdk/dist/hosting/types';

const REGION = 'us-west-1';
const s3 = new S3({
  region: REGION,
});

const FILE_HOSTING_BUKET = 'resource-hosting';
const SITE_HOSTING_BUKET = 'site-hosting';

function buildS3ResourceUrl(props: {
  region: string;
  buket: string;
  key: string;
}) {
  // e.g. - https://seamus.s3.eu-west-1.amazonaws.com/dogs/setter.png
  return `https://${props.buket}.s3.${props.region}.amazonaws.com/${props.key}`;
}

@Injectable()
export class ResourceService {
  async upload(args: {
    file: Buffer;
    mimeType: string;
    encoding: string;
    name: string;
  }): Promise<FileHostingResult> {
    const { file, mimeType, encoding, name } = args;
    // File name you want to save as in S3
    const key = `${nanoid(8)}-${name}`;
    // Setting up S3 upload parameters

    const params: S3.Types.PutObjectRequest = {
      Bucket: FILE_HOSTING_BUKET,
      Key: key,
      ACL: 'public-read',
      Body: file,
    };

    // Uploading files to the bucket
    await s3.upload(params).promise();
    const url = buildS3ResourceUrl({
      buket: FILE_HOSTING_BUKET,
      region: REGION,
      key: key,
    });

    // this is a signed url, which is valid for short time.
    // var url = s3.getSignedUrl('getObject', {
    //     Bucket: FILE_HOSTING_BUKET,
    //     Key: key,
    // });

    return <FileHostingResult>{
      url: url,
      key: key,
    };
  }
}
