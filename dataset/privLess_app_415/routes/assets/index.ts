import * as express from "express";
import multer from "multer";

const m = multer({
  storage: multer.memoryStorage(),
});

const router = express.Router();

export default router;
