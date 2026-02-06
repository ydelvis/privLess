// Config
const { config, utils } = require('serverless-authentication')

// Providers
const facebook = require('serverless-authentication-facebook')
const google = require('serverless-authentication-google')
const microsoft = require('serverless-authentication-microsoft')
const crypto = require('crypto')
const customGoogle = require('../custom-google')

// Common
const cache = require('../storage/cacheStorage')
const users = require('../storage/usersStorage')

const { createResponseData } = require('../helpers')

function createUserId(data, secret) {
  const hmac = crypto.createHmac('sha256', secret)
  hmac.update(data)
  return hmac.digest('hex')
}

/**
 * Error response
 * @param error
 */
function errorResponse(error, providerConfig) {
  const { url } = utils.errorResponse(error, providerConfig)
  return {
    statusCode: 302,
    headers: {
      Location: url
    }
  }
}

/**
 * Token response
 * @param data
 */
function tokenResponse(data, providerConfig) {
  const { url } = utils.tokenResponse(data, providerConfig)
  return {
    statusCode: 302,
    headers: {
      Location: url
    }
  }
}

/**
 * Handles the response
 * @param error
 * @param profile
 * @param state
 */
const handleResponse = async ({ profile, state }, providerConfig) => {
  try {
    await cache.revokeState(state)

    const id = createUserId(
      `${profile.provider}-${profile.id}`,
      providerConfig.token_secret
    )

    const data = createResponseData(id, providerConfig)
    const userContext = await users.saveUser(
      Object.assign(profile, { userId: id })
    )

    // saveUser can optionally return an authorizer context map
    // see http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html
    if (typeof userContext === 'object' && !Array.isArray(userContext)) {
      data.authorizationToken.payload = Object.assign(
        data.authorizationToken.payload || {},
        userContext
      )
    }
    const result = await cache.saveRefreshToken(
      id,
      data.authorizationToken.payload
    )
    return tokenResponse(
      Object.assign(data, { refreshToken: result }),
      providerConfig
    )
  } catch (exception) {
    return errorResponse({ error: exception }, providerConfig)
  }
}

/**
 * Callback Handler
 * @param proxyEvent
 * @param context
 */
async function callbackHandler(proxyEvent) {
  const event = {
    provider: proxyEvent.pathParameters.provider,
    stage: proxyEvent.requestContext.stage,
    host: proxyEvent.headers.Host,
    code: proxyEvent.queryStringParameters.code,
    state: proxyEvent.queryStringParameters.state
  }

  const providerConfig = config(event)
  let response
  switch (event.provider) {
    case 'facebook':
      response = await facebook.callbackHandler(event, providerConfig)
      break
    case 'google':
      response = await google.callbackHandler(event, providerConfig)
      break
    case 'microsoft':
      response = await microsoft.callbackHandler(event, providerConfig)
      break
    case 'custom-google':
      // See ./customGoogle.js
      response = await customGoogle.callbackHandler(event, providerConfig)
      break
    default:
      return errorResponse({ error: 'Invalid provider' })
  }
  return handleResponse(response, providerConfig)
}

module.exports = callbackHandler
