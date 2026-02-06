export interface PagePutRequest {
  id: string;
  title: string;
  document: string;
  /**
   * this part will be from multer
   */
  assets?: { [key: string]: any };
}
