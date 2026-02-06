# Contributors docs


## Architecture


## Database

MongoDB

## Search

- MongoDB query (for post service)
- MongoDB full text search (for post service)
- Elasticsearch (for external service, optional)


## API Routes

> base url: `https://posts.grida.cc/:publication/`

- `GET` /
  - get all published post (as summary)
- `GET` /:id
  - get post details
- `GET` /:id/summary
  - get post summary
- `POST` /drafts
  - create new draft
- `DELETE` /drafts/:id
  - remove draft
- `GET` /drafts
  - list drafts
- `POST` /:id/publish
  - publish draft
- `POST` /:id/schedule
  - set schedule
  - update schedule
  - remove schedule
- `POST` /:id/unlist
  - unlist (remove post)
- `GET` /unlisted
- `GET` /scheduled
- `PUT` /:id
- `PUT` /:id/body
-   save the edits
- `PUT` /:id/tags
- `GET` /:id/tags
- `PUT` /:id/category
- tags
  - `POST` /tags
  - `GET` /tags/:tag
- assets
  - `POST` /:id/assets
    - upload assets
  - `POST` /:id/assets/link
    - register linked assets
  - `DELETE` /:id/assets/link/:link
  - `DELETE` /:id/assets/:asset
  - `GET` /:id/assets
    - list assets under post
- publications
  - `GET` /publications
  - `GET` /publications/:publication
  - `POST` /publications
  - `DELETE` /publications/:publication
    - archive publication
- search
  - wip

## Models

```ts
interface Post {
  id: string;
  title: string;
  summary: string;
  thumbnail?: string;
  body: PostBody;
  cover?: string
  tags: TagLike[]
  isDraft: boolean
  category: CategoryLike
  slug: string
  visibility?: PostVisibility
  scheduledAt?: Date
  createdAt: Date
  postedAt?: Date
  locale?: String
  author?: AuthorLike
}

type Tag = {
  id: string
  name: string
}

type Category = {
  id: string
  name: string
}

type TagLike = Tag | string
type CategoryLike = '\\default\\' | Category | string
type AuthorLike = {
  id: string
}

interface PostBody{

}

enum PostVisibility {
  public = 'public',
  private =  'private',
  password = 'password_protected'
}
```


## DTOs

```ts
interface PostSummary {
  id: string
  title: string
  summary: string
  thumbnail?: string
  tags?: TagLike[]
  isDraft: boolean
  category: CategoryLike
  createdAt: Date
  postedAt?: Date
  locale?: String
  author?: AuthorLike
}
```



## Trouble shooting

- hit payload size for assets uploading? - https://theburningmonk.com/2020/04/hit-the-6mb-lambda-payload-limit-heres-what-you-can-do/