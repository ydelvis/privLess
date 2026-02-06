import { Prisma } from "@prisma/client";

export const post_summary_select: Prisma.PostSelect = {
  id: true,
  title: true,
  displayTitle: true,
  summary: true,
  slug: true,
  tags: true,
  thumbnail: true,
  category: true,
  author: true,
  readingTime: true,
  createdAt: true,
  postedAt: true,
  isListed: true,
  publicationId: true,
};
