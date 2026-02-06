# Assets for posts


**Allowed file types:**
- images
  - `image/jpeg`
  - `image/png`
  - `image/gif`
  - `image/svg+xml`
  - `image/webp`
  - `image/tiff`
  - `image/bmp`
  - `image/x-icon`
- videos
  - `video/mp4`
  - `video/webm`
  - `video/ogg`
  - `video/quicktime` (.mov)
  - `video/x-msvideo`
  - `video/x-ms-wmv`
  - `video/x-flv`
- embedable documents
  - `application/pdf`
- files (attatchments)
  - `*/*`


## Size limit

### 6mb api

By the payload limit of lambda, we can only send up to 6mb of data. to insert image bigger than 6mb, we need to use a below api.

### 6mb+ api (any)

1. request presigned url for direct upload from client
2. upload file to presigned url
3. notify server to update post (optional)