# Posts service

> posts.grida.cc

## Assets

the assets linked to a post is hosted on s3 bucket - posts-assets

- the assets are public by default.
- the assets can be private for private posts.
- the assets are public for public draft or scheduled posts.

### Object pattern

```txt
- https://posts-assets.s3.amazonaws.com/{workspace-id}/{post-id}/{asset-name}
- https://posts-assets.s3.amazonaws.com/{workspace-id}/assets/{asset-name}
- https://posts-assets.s3.amazonaws.com/default/{post-id}/{asset-name}
- https://posts-assets.s3.amazonaws.com/tmp/{asset-name}
```

## Scheduled posts


## DOM (Document Object Model)

- boring standard
  - json
  - html
  - md
- custom (for custom editors & custom renderers)


## Events

*internal infra event*
```json
{
  "id": "post-id",
  "action": "publish",
  "schedule": "2022-12-25T00:00:00Z"
}
```
- wip

## Integrations (Under development)

- Slack - on publish
- Slack - on comment
- Slack - on remove
- Github - on publish
- Webhooks

## API / SDK

- `@base-sdk/posts` (node/ts)
- rest api


## Contributors references
- https://developers.notion.com/reference/page
- https://developers.notion.com/reference/block