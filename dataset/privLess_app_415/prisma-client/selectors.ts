import { Prisma } from "@prisma/client";

export const form_summary_select: Prisma.FormSelect = {
  id: true,
  title: true,
  thumbnail: true,
  createdAt: true,
};
