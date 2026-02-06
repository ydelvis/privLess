import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export { prisma };

export * as selectors from "./selectors";
