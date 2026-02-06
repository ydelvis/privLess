// Config
const { config, utils } = require('serverless-authentication')

// Providers
const facebook = require('serverless-authentication-facebook')
const google = require('serverless-authentication-google')
const microsoft = require('serverless-authentication-microsoft')
const customGoogle = require('../custom-google')

// Common
const cache = require('../storage/cacheStorage')

/**
 * Signin Handler
 * @param proxyEvent
 * @param context
 */
async function signinHandler(proxyEvent) {
  const event = {
    provider: proxyEvent.pathParameters.provider,
    stage: proxyEvent.requestContext.stage,
    host: proxyEvent.headers.Host
  }
  const providerConfig = config(event)
  let data
  try {
    const state = await cache.createState()
    switch (event.provider) {
      case 'facebook':
        data = facebook.signinHandler(providerConfig, {
          scope: 'email',
          state
        })
        break
      case 'google':
        data = google.signinHandler(providerConfig, {
          scope: 'profile email',
          state
        })
        break
      case 'microsoft':
        data = microsoft.signinHandler(providerConfig, {
          scope: 'wl.basic wl.emails',
          state
        })
        break
      case 'custom-google':
        // See ./customGoogle.js
        data = customGoogle.signinHandler(providerConfig, { state })
        break
      default:
        data = utils.errorResponse(
          { error: `Invalid provider: ${event.provider}` },
          providerConfig
        )
    }
  } catch (exception) {
    data = utils.errorResponse({ exception }, providerConfig)
  }
  return {
    statusCode: 302,
    headers: {
      Location: data.url
    }
  }
}

module.exports = signinHandler
