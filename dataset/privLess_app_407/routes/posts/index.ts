import * as express from "express";
import multer from "multer";
import { prisma, selectors } from "../../prisma-client";
import { upload, buildPath } from "../../lib";
import type { CreateDraftPostRequest } from "../../types";
import readingTime from "reading-time";

const S3_URL = process.env.S3_URL;

const router = express.Router();

const m = multer({
  storage: multer.memoryStorage(),
});

interface ListQuery<OrderBy> {
  /**
   * The page number to fetch.
   */
  p: number;
  /**
   * The cursor
   */
  c: string;
  /**
   * The order to fetch posts.
   */
  o: OrderBy;
  /**
   * Skip the first `n` Posts.
   */
  s: number;
  /**
   * The number of Posts to fetch.
   * @default 100
   */
  t: number;
}

type UrlQueryBooleanLike = boolean | 0 | 1 | "0" | "1" | "y" | "n" | undefined;

interface PostsListQuery<OrderBy> extends ListQuery<OrderBy> {
  /**
   * when true, include - &draft | &draft=1 &draft=y
   * when false, exclude - &draft=0 | &draft=n
   * when all undefined, include with authorization
   */
  draft: UrlQueryBooleanLike;
  /**
   * when true, include - &posted | &posted=1 &posted=y
   * when false, exclude - &posted=0 | &posted=n
   * when all undefined, include with authorization
   */
  posted: UrlQueryBooleanLike;
  /**
   * when true, include - &scheduled | &scheduled=1 &scheduled=y
   * when false, exclude - &scheduled=0 | &scheduled=n
   * when all undefined, include with authorization
   */
  scheduled: UrlQueryBooleanLike;

  /**
   * target publication
   */
  publication?: string;
}

// *PUBLIC
router.get("/", async (req, res) => {
  const { t, p, s, draft, posted, scheduled, publication } =
    req.query as any as PostsListQuery<
      | "createdAt-asc"
      | "createdAt-desc"
      | "lastEditAt-asc"
      | "lastEditAt-desc"
      | "postedAt-asc"
      | "postedAt-desc"
    >;

  // 0. auth guard - publication permission
  // 1. list posts as summary
  // 2. paginate
  const posts = await prisma.post.findMany({
    where: {
      // published: true,
      isDraft: publication ? undefined : false, // if publication specified, include drafts. else, exclude drafts.
      visibility: "public", // if authenticated, show all >> ? undefined
      publicationId: publication,
      isListed: publication ? undefined : true, // only listed posts if publication is not specified
    },
    select: {
      ...selectors.post_summary_select,
      isDraft: publication ? true : undefined,
      scheduledAt: publication ? true : undefined,
    },
    orderBy: {
      postedAt: "desc",
    },
    take: t ?? 100,
  });

  res.json(posts);
});

router.delete("/:id", async (req, res) => {
  // TODO: add auth guard
  const { id } = req.params;
  const candelete = prisma.post.findFirst({
    where: {
      id,
      // TODO: allow delete on only unlisted or draft post.
    },
  });

  if (candelete) {
    await prisma.post.delete({
      where: {
        id,
      },
    });
    res.json({ id: id });
  } else {
    res.status(400).json({ message: "cannot delete" });
  }
});

router.post("/unlisted", async (req, res) => {
  // 0. auth guard - post permission
  // 1. get all unlisted posts (non draft)
  const posts = await prisma.post.findMany({
    where: {
      // published: true,
      isDraft: false,
    },
    select: selectors.post_summary_select,
  });

  res.status(200).json({
    // TODO:
  });
});

router.post("/scheduled", async (req, res) => {
  // 1. get all scheduled posts (non draft)

  const posts = await prisma.post.findMany({
    where: {
      isDraft: false,
      // published: false,
      // postedAt is null
      scheduledAt: {
        gte: new Date(),
      },
    },
    select: selectors.post_summary_select,
  });

  res.status(200).json({
    // TODO:
  });
});

// *PUBLIC
router.get("/:id", async (req, res) => {
  const { id } = req.params;
  const { preview } = req.query;

  const _q_show_preview =
    preview === "true" || preview === "1" || preview === "y";

  // if preview, show drafting content if already published. if not, show the post itself (a draft)

  // 1. fetch post detail (for render & edit)
  const post = await prisma.post.findUnique({
    where: {
      id: id,
    },
  });

  const isPosted =
    // next/prev query requires postedAt to be set
    post.postedAt !== null &&
    // extra explicit safety guard
    !post.isDraft;

  if (isPosted) {
    const q = {
      id: {
        not: id,
      },
      publication: {
        id: post.publicationId,
      },
      isDraft: false,
      isListed: true,
      scheduledAt: null,
    };

    const prev = await prisma.post.findFirst({
      where: {
        ...q,
        postedAt: {
          lte: post.postedAt,
        },
      },
      orderBy: {
        postedAt: "desc",
      },
      select: selectors.post_summary_select,
    });

    const next = await prisma.post.findFirst({
      where: {
        ...q,
        postedAt: {
          gte: post.postedAt,
        },
      },
      orderBy: {
        postedAt: "asc",
      },
      select: selectors.post_summary_select,
    });

    res.json({
      ...post,
      // prev & next listed post
      previous: prev,
      next: next,
    });
  }

  res.json({
    ...post,
  });
});

router.post("/:id/publish", async (req, res) => {
  const { id } = req.params;
  const { visibility } = req.body;
  // 0. auth guard - post permission
  // 1. validate current data
  // 2. emmit event

  const _post = await prisma.post.findUnique({
    where: {
      id: id,
    },
    select: {
      body: true,
      title: true,
      draft: true,
      postedAt: true,
    },
  });

  const rt = _post.body["html"] ? readingTime(_post.body["html"]) : undefined;
  const rts = rt?.time; // time in seconds

  const post = await prisma.post.update({
    where: {
      id: id,
    },
    data: {
      isDraft: false,
      draft: null, // clear draft
      // region update production data
      title: _post.draft?.title ?? undefined, // update title if draft exists
      displayTitle: _post.draft?.displayTitle ?? _post.title, // update preview if draft exists, if not use the same value as title
      summary: _post.draft?.summary ?? undefined, // update summary if draft exists
      body: _post.draft?.body ?? undefined, // update body if draft exists
      cover: _post.draft?.cover ?? undefined, // update body if draft exists
      // endregion update production data
      postedAt: _post.postedAt ? undefined : new Date(), // if already posted (with date info), don't update the date. // also do not update the postedAt as well, if previously unlisted.
      isListed: true,
      lastEditAt: new Date(),
      visibility: visibility ?? "public",
      readingTime: rts,
      scheduledAt: null, // clear schedule
    },
  });

  res.status(200).json(post);
});

router.post("/:id/unlist", async (req, res) => {
  const { id } = req.params;

  // 0. auth guard - post permission
  // 1. unlist a published post (only works for published posts)
  const post = await prisma.post.update({
    where: {
      id: id,
    },
    data: {
      isListed: false,
    },
  });

  res.json(post);
});

router.post("/:id/visibility", async (req, res) => {
  const { id } = req.params;
  const { visibility } = req.body; // as ??

  // 0. auth guard - post permission
  // 1. unlist a published post (only works for published posts)
  const post = await prisma.post.update({
    where: {
      id: id,
    },
    data: {
      visibility: visibility,
    },
  });

  res.status(200).json({
    // TODO:
  });
});

router.post("/:id/title", async (req, res) => {
  const { id } = req.params;
  const { title } = req.body; // as ??

  // 0. auth guard - post permission
  // 1. update the post title
  const post = await prisma.post.update({
    where: {
      id: id,
    },
    data: {
      title: title,
    },
  });

  res.status(200).json(post);
});

router.post("/:id/summary", async (req, res) => {
  const { id } = req.params;
  const { title, summary } = req.body;
  // 0. auth guard - post permission
  // 1. update the post title
  const post = await prisma.post.update({
    where: {
      id: id,
    },
    data: {
      title: title && title, // can also update title by summary update, but optional.
      summary: summary,
    },
  });

  res.status(200).json({
    id: post.id,
    title: post.title,
    summary: post.summary,
  });
});

/**
 * set the thumbnail (put)
 *
 * methods:
 * - 1: use the existing asset (w/id)
 * - 2: use the existing asset (w/url or key)
 * - 3: upload new asset for thumbnail
 */
router.put("/:id/thumbnail", m.single("thumbnail"), async (req, res) => {
  const { id } = req.params as { id: string };
  if (req.file) {
    try {
      const thumbnail = req.file;
      const { buffer, originalname, mimetype } = thumbnail;
      const ext = originalname.split(".").pop();
      const name = ext ? "thumbnail." + ext : "thumbnail";
      const path = "posts/" + id + "/" + name;
      const s3path = S3_URL + "/" + path;
      await upload(
        "posts/" + id,
        { body: buffer, mimetype: mimetype ?? "image/*" },
        name
      );

      await prisma.post.update({
        where: { id },
        data: {
          thumbnail: s3path,
        },
      });

      res.json({
        thumbnail: encodeURI(s3path),
      });
    } catch (e) {
      console.error("error while putting thumbnail with multipart upload", e);
    }

    return;
  }

  if (req.body) {
    // 1. use existing asset (already hosted)
    // TODO:
    return;
  }
  //
  // TODO:
  // 1. remove the previous thumbnail if not referenced in the body.
});

/**
 * get the available thumbnails for this post (uploaded assets)
 *
 * 1. get the post's body and cover
 * 2. get the available assets inside the body
 *  - this is required because on the client side, we have to make user select asset that is present on the current post (or draft).
 * 3. return the available thumbnail data
 */
router.get("/:id/thumbnails", async (req, res) => {
  const { id } = req.query;

  const post = await prisma.post.findUnique({
    where: {
      id: id as string,
    },
    select: {
      body: true,
      thumbnail: true,
      draft: true,
      cover: true,
      assets: true,
    },
  });

  const { body, draft, assets, thumbnail, cover } = post;
  // parse the html, find the asset
  const acceptable = [];

  // find asset used in the html body. (parse, find in img tag)

  body.html;
  draft.body.html;
});

router.put("/:id/draft", async (req, res) => {
  const { id } = req.params;
  const { title, body, displayTitle, summary, cover } = req.body;
  const { r } = req.query;

  const draft = await prisma.post.update({
    where: {
      id: id,
    },
    data: {
      lastEditAt: new Date(),
      isDraft: false, // when draft (anothor branch) is created, set isDraft of main to false (setting this explicitly for future reference. don't get confused!)
      draft: {
        title: title ?? undefined,
        body: body ?? undefined,
        displayTitle: displayTitle ?? undefined,
        summary: summary ?? undefined,
      },
    },
  });

  switch (r) {
    case "*":
      res.status(200).json({
        id: id,
        ...draft,
      });
    case undefined:
    default:
      res.status(200).json({
        id,
        updated: {
          length: draft.body["html"]?.length ?? 0,
        },
      });
  }
});

router.put("/:id/body", async (req, res) => {
  const { id } = req.params;
  const { r } = req.query;
  const { html } = req.body;

  // 0. auth guard - post permission
  // 1. update the post body (with standard format)
  const post = await prisma.post.update({
    where: {
      id: id,
    },
    data: {
      lastEditAt: new Date(),
      body: {
        html,
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
          length: post.body["html"]?.length ?? 0,
        },
      });
  }
});

router.put("/:id/custom-body", async (req, res) => {
  const { id } = req.params;
  const { r } = req.query;
  const body = req.body; // as ??

  // 0. auth guard - post permission
  // 1. update the post body (with custom scheme)
  const post = await prisma.post.update({
    where: {
      id: id,
    },
    data: {
      body: body,
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

router.put("/:id/tags", async (req, res) => {
  const { id } = req.params;
  const { tags } = req.body;

  // 0. auth guard - post permission
  // 1. update the post tags
  const post = await prisma.post.update({
    where: {
      id: id,
    },
    data: {
      // TODO: filter the tag type (is it refernce or string?)
      tags: tags,
    },
  });

  res.json({ tags: post.tags });
});

router.post("/:id/schedule", async (req, res) => {
  const { id } = req.params;
  const { at } = req.body; // as ??

  // 0. auth guard - post permission
  // 1. update the post schedule
  const post = await prisma.post.update({
    where: {
      id: id,
    },
    data: {
      scheduledAt: at,
    },
  });
});

router.put(`/:id`, m.array("assets"), async (req, res) => {
  const { id } = req.params;
  const assets = req.files;

  try {
    // const path = buildPath("??", {
    //   post: id,
    // });

    // if (assets && Array.isArray(assets)) {
    //   const uploads: Array<Promise<any>> = [];
    //   assets.forEach((asset) => {
    //     const { buffer, originalname, mimetype } = asset;
    //     uploads.push(
    //       uploadAssets({
    //         path,
    //         file: { body: buffer, mimetype: mimetype ?? "image/png" },
    //         key: originalname,
    //       })
    //     );
    //   });
    //   const uploadedAssets = await Promise.all(uploads);
    // }

    res.json({
      status: "ok",
      id: id,
    });
  } catch (e) {
    res.status(500).json({
      status: "error",
      message: e.message,
    });
  }
});

export default router;
