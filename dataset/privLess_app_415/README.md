# Forms service

> forms.grida.cc

## Assets

the assets linked to a forms is hosted on s3 bucket - forms-cms

- the assets are public by default.
- the assets from responses are private by default.

### Object pattern

```txt
- https://forms-cms.s3.amazonaws.com/forms/{form-id}/{asset-name}
- https://forms-cms.s3.amazonaws.com/responses/{form-id}/{asset-name}
```


## DOM (Document Object Model)

- boring standard
  - json
  - html
  - md
- reflect-ui standard
  - json

## Events

*internal infra event*
```json
{
  "id": "form-id",
  "action": "publish",
  "schedule": "2022-12-25T00:00:00Z"
}
```

```json
{
  "id": "response-id",
  "action": "submit",
  "schedule": "2022-12-25T00:00:00Z"
}
```

## Integrations (Under development)

- Slack - on publish
- Slack - on submit
- Github - on publish
- Webhooks

## API / SDK

- `@base-sdk/forms` (node/ts)
- rest api


