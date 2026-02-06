/**
 * example
 *
```
{
    id: 'U6nlG0Y5sfs',
    created_at: '2018-06-20T01:22:40-04:00',
    updated_at: '2020-10-21T01:04:19-04:00',
    promoted_at: '2018-06-21T11:39:13-04:00',
    width: 2303,
    height: 3594,
    color: '#060205',
    blur_hash: 'LvOd3noLoLju|7f7WVjuO,a{WUj[',
    description: 'Pink Wall Full of Dogs',
    alt_description: 'litter of dogs fall in line beside wall',
    urls: [Object],
    links: [Object],
    categories: [],
    likes: 1203,
    liked_by_user: false,
    current_user_collections: [],
    sponsorship: null,
    user: [Object],
    tags: [Array]
},
```
 */
interface UnsplashImage {
  id: string;
  created_at: Date;
  updated_at: Date;
  width: number;
  height: number;
  color: string;
  description: string;
  alt_description: string;
  urls: UnsplashImageUrlMap;
  links: UnsplashLinkMap;
  tags: Array<UnsplashTag>;
}

interface UnsplashImageUrlMap {
  raw: string;
  regular: string;
  small: string;
  thumb: string;
}

interface UnsplashResponse {
  total: number;
  total_pages: number;
  results: Array<UnsplashImage>;
}

/**
 * example
```
{
    self: 'https://api.unsplash.com/photos/KIqJfzbII9w',
    html: 'https://unsplash.com/photos/KIqJfzbII9w',
    download: 'https://unsplash.com/photos/KIqJfzbII9w/download',
    download_location: 'https://api.unsplash.com/photos/KIqJfzbII9w/download'
}
```
 */
interface UnsplashLinkMap {
  self: string;
  html: string;
  download: string;
  download_location: string;
}

/**
 * example
```
{
    type: 'landing_page',
    title: 'dog',
    source: {
      ancestry: [Object],
      title: 'Dog Images & Pictures',
      subtitle: 'Download free dog images',
      description: "Man's best friend is something to behold in all forms: gorgeous Golden Retrievers, tiny yapping chihuahuas, fearsome pitbulls. Unsplash's community of incredible photographers has helped us curate an amazing selection of dog images that you can access and use free of charge.",
      meta_title: 'Dog Pictures | Download Free Images on Unsplash',
      meta_description: 'Choose from hundreds of free dog pictures. Download HD dog photos for free on Unsplash.',
      cover_photo: [Object]
    }
}
```
 */
interface UnsplashTag {
  type: string;
  title: string;
  source: {
    ancestry: any;
    title: string;
    subtitle: string;
    description: string;
    cover_photo: any;
  };
}
