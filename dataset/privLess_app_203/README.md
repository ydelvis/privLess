# Serverless Blog Workshop by SC5

Example backend project for AWS - Serverless hackathon.

Project is compatible with Serverless v1

## Step by step instructions for building the project with Serverless Framework v1.5

### Setup project

* Create the service from the `sc5-serverless-boilerplate`
```bash
> sls install -u https://github.com/SC5/sc5-serverless-boilerplate -n serverless-blog
> cd serverless-blog
> npm install
```

### Set up storage (DynamoDB)

* Un-comment `Resources:` and `resources:` in `serverless.yml`.

```
# DynamoDB Blog table for workshop
    BlogTable:
      Type: AWS::DynamoDB::Table
      DeletionPolicy: Retain
      Properties:
        AttributeDefinitions:
          - AttributeName: id
            AttributeType: S
        KeySchema:
          - AttributeName: id
            KeyType: HASH
        ProvisionedThroughput:
          ReadCapacityUnits: 1
          WriteCapacityUnits: 1
        TableName: ${self:provider.environment.TABLE_NAME}
```

### Create function and endpoints

* Create the function
```bash
sls create function -f posts --handler posts/index.handler
```

* Register HTTP endpoints by adding the following to the function definition in `serverless.yml`
```
    events:
      - http:
          path: posts
          method: get          
          cors: true
          integration: lambda
      - http:
          path: posts
          method: posts
          cors: true
          integration: lambda
       - http:
          path: posts/{id}
          method: put
          cors: true
          integration: lambda
      - http:
          path: posts/{id}
          method: delete
          cors: true
          integration: lambda
```

### Implement the functionality

* Copy `posts/index.js` and `posts/BlogStorage.js` from this repo to your service (`posts` folder)

### Deploy and test

* Deploy the resources (and functions) using

```
sls deploy
````

* Copy tests from `test/posts.js` in this repo to your service
* Run `serveless-mocha-plugin` tests

```
sls invoke test --region us-east-1 --stage dev
```

### Set up your blog application

* Launch the blog application
* Enter the service Url (https://..../posts). The service URL can be retrieved using
```
sls info
```

#### Enjoy, your ready to go!

# Feedback
mikael.puittinen@sc5.io
