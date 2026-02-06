import * as express from "express";
import multer from "multer";
import { prisma, selectors } from "../../prisma-client";
import { uploadAssets, buildPath } from "../../lib";

const router = express.Router();

const m = multer({
  storage: multer.memoryStorage(),
});

router.post("/", async (req, res) => {
  const { title, description } = req.body;
  // 0. auth guard - workspace permission
  // 1. create new form
  const form = await prisma.form.create({
    data: {
      config: {},
      title,
      description,
    },
  });

  res.json(form);
});

// *PUBLIC
router.get("/", async (req, res) => {
  // 0. auth guard - workspace permission
  // 1. list forms as summary
  // 2. paginate
  const forms = await prisma.form.findMany({
    where: {},
    select: selectors.form_summary_select,
    orderBy: {
      createdAt: "desc",
    },
    take: 100,
  });

  res.status(200).json(forms);
});

// *PUBLIC
router.get("/:id", async (req, res) => {
  const { id } = req.params;

  // 1. fetch post detail (for render & edit)

  const form = await prisma.form.findUnique({
    where: {
      id: id,
    },
  });

  res.status(200).json(form);
});

router.post("/:id/publish", async (req, res) => {
  const { id } = req.params;
  // 0. auth guard - workspace permission
  // 1. validate current data
  // 2. emmit event

  const form = await prisma.form.update({
    where: {
      id: id,
    },
    data: {
      postedAt: new Date(),
      scheduledAt: null, // clear schedule
    },
  });

  res.status(200).json(form);
});

router.post("/:id/archive", async (req, res) => {
  const { id } = req.params;
  const { archive } = req.body ?? {}; // can also unarchive with this route (body is optional)

  // 0. auth guard - form permission
  // 1. unlist a published post (only works for published posts)
  const form = await prisma.form.update({
    where: {
      id: id,
    },
    data: {
      postedAt: null, // clear
      archived: archive ?? true, // default to true
    },
  });

  res.status(200).json(form);
});

router.post("/:id/title", async (req, res) => {
  const { id } = req.params;
  const { title } = req.body; // as ??

  // 0. auth guard - post permission
  // 1. update the post title
  const form = await prisma.form.update({
    where: {
      id: id,
    },
    data: {
      title: title,
    },
  });

  res.status(200).json(form);
});

router.post("/:id/description", async (req, res) => {
  const { id } = req.params;
  const { title, description } = req.body;
  // 0. auth guard - form permission
  // 1. update the form title
  const form = await prisma.form.update({
    where: {
      id: id,
    },
    data: {
      title: title && title, // can also update title by summary update, but optional.
      description,
    },
  });

  res.status(200).json({
    id: form.id,
    title: form.title,
    summary: form.description,
  });
});

router.put("/:id/body", async (req, res) => {
  const { id } = req.params;
  const { r } = req.query;
  const { blocks } = req.body; // as ??

  // 0. auth guard - post permission
  // 1. update the post body (with standard format)
  const post = await prisma.form.update({
    where: {
      id: id,
    },
    data: {
      body: {
        $scheme: "boring",
        blocks,
        // TODO:
      },
    },
  });

  switch (r) {
    case "*":
      res.status(200).json(post);
    case undefined:
    default:
      res.status(200).json({
        id,
        updated: {
          length: post.body["blocks"]?.length ?? 0,
        },
      });
  }
});

router.get("/:id/responses", async (req, res) => {
  const { id } = req.params;
  const responses = await prisma.response.findMany({
    where: {
      formId: id,
    },
  });

  res.json(responses);
});

router.get("/:id/responses/:rid", async (req, res) => {
  const { rid } = req.params;
  const responses = await prisma.response.findUnique({
    where: {
      id: rid,
    },
  });

  res.json(responses);
});

export default router;
