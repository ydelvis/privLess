const signinHandler = require('./lib/handlers/signinHandler')
const callbackHandler = require('./lib/handlers/callbackHandler')
const refreshHandler = require('./lib/handlers/refreshHandler')
const authorizeHandler = require('./lib/handlers/authorizeHandler')
const { setupSchemaHandler } = require('./lib/storage/fauna/faunaUser')

module.exports.signin = async (event) => signinHandler(event)

module.exports.callback = async (event) => callbackHandler(event)

module.exports.refresh = async (event) => refreshHandler(event)

module.exports.authorize = async (event) => authorizeHandler(event)

module.exports.schema = (event, context, cb) => setupSchemaHandler(event, cb)
