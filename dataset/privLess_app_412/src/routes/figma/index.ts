import * as express from "express";
import * as multer from "multer";
import { uploadAssets, uploadDocument, buildPath } from "../../core";
import type { PagePutRequest } from "../../types";
const router = express.Router();

const PAGE_HOST = process.env.PAGE_HOST ?? "https://pages.grida.co";

const m = multer({
  storage: multer.memoryStorage(),
});

router.put(`/:filekey`, m.array("assets"), async (req, res) => {
  const { filekey } = req.params;
  const { id, document } = req.body as PagePutRequest;
  const assets = req.files;

  const path = buildPath(filekey, "figma");

  const uploads: Array<Promise<any>> = [];

  // html document file (without .html extension)
  uploads.push(uploadDocument({ path, document, id }));

  if (assets && Array.isArray(assets)) {
    assets.forEach((asset) => {
      const { buffer, originalname, mimetype } = asset;
      uploads.push(
        uploadAssets({
          path,
          file: { body: buffer, mimetype: mimetype ?? "image/png" },
          key: originalname,
        })
      );
    });
  }

  try {
    await Promise.all(uploads);
    res.json({
      status: "ok",
      page_path: path + "/" + id,
      page_id: id,
      page_url: `${PAGE_HOST}/${path}/${id}`,
    });
  } catch (e) {
    res.status(500).json({
      status: "error",
      message: e.message,
    });
  }
});

export default router;
