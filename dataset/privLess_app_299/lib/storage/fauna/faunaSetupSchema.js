// call this with `STAGE=dev npm run setup:fauna` before anything else

let userClassName
let config

const faunadb = require('faunadb')
const fs = require('fs')
const yaml = require('js-yaml') // eslint-disable-line import/no-extraneous-dependencies

const readFile = (filePath) =>
  new Promise((resolve, reject) => {
    fs.readFile(filePath, 'utf8', (error, data) => {
      if (error) return reject(error)
      return resolve(data)
    })
  })

const q = faunadb.query
const setupSchema = () => {
  const client = new faunadb.Client(config)
  return client
    .query(q.CreateClass({ name: 'auth_cache' }))
    .then(() =>
      client.query(
        q.Create(q.Ref('indexes'), {
          name: 'auth_cache',
          source: q.Class('auth_cache'),
          terms: [{ field: [ 'data', 'token' ] }],
          unique: true
        })
      ))
    .then(() => client.query(q.CreateClass({ name: userClassName })))
    .then(() =>
      client.query(
        q.Create(q.Ref('indexes'), {
          name: 'auth_userId',
          source: q.Class(userClassName),
          terms: [{ field: [ 'data', 'userId' ] }],
          unique: true
        })
      ))
    .then(() =>
      client.query(
        q.Create(q.Ref('indexes'), {
          // this index is optional but useful in development for browsing users
          name: `all_${userClassName}`,
          source: q.Class(userClassName)
        })
      ))
}

const run = async () => {
  const file = await readFile('./authentication/env.yml')
  const yamlData = yaml.safeLoad(file)
  const env = yamlData[process.env.STAGE]
  userClassName = env.USERS_CLASS_NAME || 'users' // should be shared with content app
  config = { secret: env.FAUNADB_SECRET }
  process.env.FAUNADB_SECRET = env.FAUNADB_SECRET
  try {
    await setupSchema()
  } catch (exception) {
    console.error(JSON.stringify(exception, null, 2)) // eslint-disable-line no-console
  }
}

run()
