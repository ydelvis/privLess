import * as express from "express";
import multer from "multer";
import assert from "assert";
import { makeClient, upload, buildPath } from "../../lib";
import { nanoid } from "nanoid";

const S3_URL = process.env.S3_URL;
const router = express.Router();

const m = multer({
  storage: multer.memoryStorage(),
});

router.post("/:id/upload", m.array("files", 25), async (req, res) => {
  const { id: postid } = req.params as { id: string };
  const assets = req.files ?? (req.file && [req.file]);

  const uploads: Array<Promise<any>> = [];
  const results = {};

  if (assets && Array.isArray(assets)) {
    assets.forEach((asset) => {
      const { buffer, originalname, mimetype } = asset;
      const ext = originalname.split(".").pop();
      const cuid = nanoid();
      const name = ext ? cuid + "." + ext : cuid;
      const path = "posts/" + postid + "/" + name;
      const s3path = S3_URL + "/" + path;
      uploads.push(upload(path, { body: buffer, mimetype: mimetype }));
      results[originalname] = s3path;
    });
  }

  try {
    await Promise.all(uploads);
    // TODO: db injection is not yet supported.
    res.json({
      post_id: postid,
      assets: results,
    });
  } catch (e) {
    res.status(500).json({
      status: "error",
      message: e.message,
    });
  }
});

// request the asset uploader client
router.get("/client", async (req, res) => {
  const { post } = req.query; // post id to link the asset to.
  const { post: _post, mimetype, key, encoding } = req.body;

  const postid = post ?? _post;
  assert(postid, '"post" is required');

  const path = buildPath(postid);
  const abskey = path + "/" + key;

  const expiresIn = 3600;
  const signedUrl = await makeClient(abskey, {
    encoding,
    mimetype,
  });

  res.json({
    url: signedUrl,
    expires_in: expiresIn,
    expires_at: new Date(Date.now() + expiresIn * 1000),
  });
});

export default router;
