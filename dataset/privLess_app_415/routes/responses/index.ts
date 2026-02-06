import * as express from "express";
import { prisma } from "../../prisma-client";

const router = express.Router();

router.post("/start", (req, res) => {
  // create new response session for assets uploading & saving etc..
});

router.post("/:id/submit", (req, res) => {
  // submit (close) the response with session
});

router.post("/submit", async (req, res) => {
  // submit the response (w/o session)
  const { form, landedAt, answers, platform } = req.body;

  try {
    const response = await prisma.response.create({
      data: {
        form: {
          connect: {
            id: form,
          },
        },
        answers,
        metadata: {
          ip: req.ip,
          ua: req.headers["user-agent"],
          // referer: req.headers.referer,
          platform: platform ?? "web",
        },
        landedAt,
        submittedAt: new Date(),
      },
    });

    res.status(202).json(response);
  } catch (e) {
    console.error(e)
    res.status(400).json({
      error: "cannot create new response (metadata may be invalid)",
    });
  }
});

export default router;
