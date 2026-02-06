import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Redirect,
  Res,
} from "@nestjs/common";
import * as path from "path";

import {
  UrlShortenRequest,
  UrlShortenResult,
} from "@bridged.xyz/client-sdk/dist/url/types";
import { AppService } from "./app.service";
import { checkIfValidUrl } from "./utils";

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(@Res() res) {
    const file = path.resolve(
      process.env.LAMBDA_TASK_ROOT as string,
      "_optimize",
      process.env.AWS_LAMBDA_FUNCTION_NAME as string,
      "web",
      "index.html"
    );
    res.sendFile(file);
  }

  @Get(":id")
  @Redirect("https://grida.co/", 302) // the default redirection
  async getRedirect(@Param() params) {
    const id = params.id;
    const redirect = await this.appService.getRedirect(id);
    return {
      url: redirect,
    };
  }

  @Post("/short")
  async postShort(@Body() req: UrlShortenRequest): Promise<UrlShortenResult> {
    const url = req.url;
    if (checkIfValidUrl(url)) {
      const result = await this.appService.createRecord(url);
      return result;
    }
    throw `the url: ${url} is not a valid url.`;
  }
}
