import {
  Controller,
  Post,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';

import { ResourceService } from './resource.service';

@Controller('resources')
export class ResourceController {
  constructor(private readonly resourceService: ResourceService) {}

  @Post('/')
  @UseInterceptors(FileInterceptor('file'))
  async upload(@UploadedFile() file) {
    console.log(
      `uploading file..`,
      file.originalname,
      file.mimetype,
      file.encoding,
    );
    return await this.resourceService.upload({
      file: file.buffer,
      encoding: file.encoding,
      name: file.originalname ? file.originalname : '',
      mimeType: file.mimetype ? file.mimetype : '*/*',
    });
  }
}
