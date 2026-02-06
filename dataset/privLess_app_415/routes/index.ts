import * as express from "express";
import router_forms from "./forms";
import router_assets from "./assets";
import router_responses from "./responses";
import router_export from "./export";

const router = express.Router();

router.use("/", router_forms);
router.use("/responses", router_responses);
router.use("/assets", router_assets);
router.use("/export", router_export);

export default router;
