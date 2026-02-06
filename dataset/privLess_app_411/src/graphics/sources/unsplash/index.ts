import Unsplash from 'unsplash-js';

interface UnsplashResponse {
  results: {
    tags: {
      source: string;
    }[];
  }[];
}

const unsplash = new Unsplash({ accessKey: process.env.UNSPLASH_ACCESS_KEY });

async function getRandomFromTopic(topic: string) {
  const res: UnsplashResponse = await (
    await unsplash.search.photos(topic, 1, 1)
  ).json();
  console.log(res.results[0].tags[0].source);
  return res;
}

getRandomFromTopic('dogs');
