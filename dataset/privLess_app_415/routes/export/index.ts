import * as express from "express";
const router = express.Router();
import { prisma } from "../../prisma-client";
import { stringify } from "csv-stringify";

// exports the responses of the form
router.get("/:id", async (req, res) => {
  const { id } = req.params;
  const { f } = req.query;

  const form = await prisma.form.findUnique({
    where: { id },
    select: {
      title: true,
    },
  });

  const responses = await prisma.response.findMany({
    where: {
      formId: id,
    },
  });

  const filename = `grida-forms-export-${
    form.title
  }-${new Date().toISOString()}.${f}`;

  switch (f) {
    case "csv": {
      const stringifier = stringify({
        header: true,
        columns: {
          time: "time",
        },
      });
      stringifier.write([]);
      stringifier.end();
    }
    case "json": {
      const payload = JSON.stringify(responses);
      break;
    }
    case "xls":
    case "xlsx": {
    }
    default: {
    }
  }

  res.json(responses);
});

export default router;
