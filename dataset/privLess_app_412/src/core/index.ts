import * as AWS from "@aws-sdk/client-s3";
import { PutObjectCommand } from "@aws-sdk/client-s3";

const PAGE_HOSTING_BUKET = "page-hosting";
const client = new AWS.S3({});

export async function upload(
  path: string,
  file: { body: string | Buffer; mimetype?: string; encoding?: string },
  key: string
) {
  const command = new PutObjectCommand({
    Bucket: PAGE_HOSTING_BUKET,
    Key: path + "/" + key,
    Body: file.body,
    ContentEncoding: file.encoding,
    ContentType: file.mimetype,
    ACL: "public-read",
  });
  return await client.send(command);
}

export async function uploadAssets({
  path,
  file,
  key,
}: {
  path: string;
  file: { body: Buffer; mimetype?: string };
  key: string;
}) {
  // this won't work locally. with sls offline. it's a serverless' issue
  return await upload(path, { body: file.body, mimetype: file.mimetype }, key);
}

export async function uploadDocument({
  path,
  id,
  document,
}: {
  path: string;
  id: string;
  document: string;
}) {
  return await upload(path, { body: document, mimetype: "text/html" }, id);
}

export function buildPath(key: string, service: string) {
  switch (service) {
    case "figma":
      return `f-${key}`;
    case "sketch":
      return `s-${key}`;
    case "invision":
      return `i-${key}`;
    case "xd":
      return `xd-${key}`;
    default:
      throw "Unknown service";
  }
}
