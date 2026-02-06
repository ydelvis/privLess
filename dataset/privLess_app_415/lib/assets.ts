export async function uploadAssets({}: { path: string; file; key: string }) {}
export async function removeAssets() {}
export function buildPath(
  key,
  {
    publication,
    post,
  }: {
    publication?: string;
    post: string;
  }
): string {
  return "";
}
