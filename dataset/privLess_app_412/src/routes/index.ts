import * as express from "express";
import router_figma from "./figma";

const router = express.Router();

router.use("/figma", router_figma);

export default router;
