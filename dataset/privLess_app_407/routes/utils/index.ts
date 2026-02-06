import * as express from "express";
import readingTime from "reading-time";

const router = express.Router();

router.post("/reading-time", (req, res) => {
  const { text, html, md, markdown } = req.body;
  const payload = text ?? html ?? md ?? markdown;
  const rt = readingTime(payload);
  res.json(rt);
});

export default router;
