// Config
const { config, utils } = require('serverless-authentication')

const policyContext = (data) => {
  const context = {}
  Object.keys(data).forEach((k) => {
    if (k !== 'id' && [ 'boolean', 'number', 'string' ].indexOf(typeof data[k]) !== -1) {
      context[k] = data[k]
    }
  })
  return context
}

// Authorize
const authorize = async (event) => {
  const stage = event.methodArn.split('/')[1] || 'dev' // @todo better implementation
  let error = null
  let policy
  const { authorizationToken } = event
  if (authorizationToken) {
    try {
      // this example uses simple expiration time validation
      const providerConfig = config({ provider: '', stage })
      const data = utils.readToken(authorizationToken, providerConfig.token_secret)
      policy = utils.generatePolicy(data.id, 'Allow', event.methodArn)
      policy.context = policyContext(data)
    } catch (err) {
      error = 'Unauthorized'
    }
  } else {
    error = 'Unauthorized'
  }
  if (error) {
    throw new Error(error)
  }
  return Promise.resolve(policy)
}


module.exports = authorize
