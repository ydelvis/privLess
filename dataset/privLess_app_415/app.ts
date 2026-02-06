import express from "express";
import useragent from "express-useragent";
import cors from "cors";
import bodyParser from "body-parser";
import router from "./routes";

const app = express();

app.use(cors());

app.use(useragent.express());

app.use(bodyParser.json());

app.use(router);

export { app };
