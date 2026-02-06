import * as AWS from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { PutObjectCommand } from "@aws-sdk/client-s3";
const POSTS_CMS_BUKET = "cms-posts";
const client = new AWS.S3({});

export async function upload(
  path: string,
  file: { body: string | Buffer; mimetype?: string; encoding?: string },
  key?: string
) {
  const command = new PutObjectCommand({
    Bucket: POSTS_CMS_BUKET,
    Key: key ? path + "/" + key : path,
    Body: file.body,
    ContentEncoding: file.encoding,
    ContentType: file.mimetype,
    ACL: "public-read",
  });
  return await client.send(command);
}

/**
 * use this for exporting the post as html file for faster access and downloading.
 * @returns
 */
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

export async function makeClient(
  abskey: string,
  { encoding, mimetype }: { encoding; mimetype }
) {
  const command = new PutObjectCommand({
    Bucket: POSTS_CMS_BUKET,
    Key: abskey,
    Body: "BODY",
    ContentEncoding: encoding,
    ContentType: mimetype,
    ACL: "public-read", // TODO: follow the post visibility -> but for to be visible on editor, it needs to be public...hmm
  });

  // Create the presigned URL.
  const expiresIn = 3600;
  const signedUrl = await getSignedUrl(client, command, {
    expiresIn: expiresIn,
  });

  return signedUrl;
}

export async function removeAssets() {}

export function buildPath(postid: string) {
  return `posts/${postid}`;
}
