import { prisma, selectors } from "../../prisma-client";
import * as express from "express";

const router = express.Router();

// list all drafts (no pagination, max limit)
router.get("/", async (req, res) => {
  // 0. auth guard - publication check
  // 1. list all drafts (as summary)

  const { publication } = req.query;

  const posts = await prisma.post.findMany({
    where: {
      publication: publication
        ? {
            id: publication as string,
          }
        : undefined,
      isDraft: true,
      visibility: publication ? undefined : "public",
    },
    select: selectors.post_summary_select,
  });

  res.json(posts);
});

// create new draft
router.post("/", async (req, res) => {
  const { title, publication, visibility } = req.body; // as ??
  // 1. create new draft
  // 2. return draft id

  const post = await prisma.post.create({
    data: {
      publication: {
        connect: {
          id: publication,
        },
      },
      // we can create new draft document optionally with title.
      title: title ?? "",
      displayTitle: title,
      body: {},
      isDraft: true,
      isListed: false,
      visibility: visibility ?? "private",
      author: undefined, // TODO:
    },
  });

  res.status(201).json(post);
});

// create new draft
router.delete("/:id", async (req, res) => {
  const { id } = req.params;
  // 0. auth guard - post permission
  // 1. check if draft
  // 2. delete draft
  // 3. delete associated assets

  const removed = await prisma.post.deleteMany({
    where: {
      id: id,
      isDraft: true,
    },
  });

  if (removed.count) {
    res.status(202).json({});
  } else {
    res.status(400).json({
      error: "this post cannot be removed (already published or non existent)",
    });
  }
});

router.post("/discard", (req, res) => {
  // discard draft
});
export default router;
