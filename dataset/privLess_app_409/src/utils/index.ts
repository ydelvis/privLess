import { URL } from 'url';
import { nanoid } from 'nanoid';

/**
 * check if givven url is a valid, and the host does not conficts.
 * @param s
 */
export function checkIfValidUrl(s): boolean {
  try {
    const url = new URL(s);
    console.log(url.host);
    return !url.host.includes(process.env.HOST);
  } catch (err) {
    return false;
  }
}

// calculate it here. https://zelark.github.io/nano-id-cc/
const RAND_RANGE = 16;

export function generateHash() {
  return nanoid(RAND_RANGE);
}

export function buildShortUrl(id: string, host: string) {
  return `https://${host}/${id}`;
}
