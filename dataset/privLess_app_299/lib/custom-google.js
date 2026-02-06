

const { Provider, Profile } = require('serverless-authentication')

const signinHandler = (config, options) => {
  const customGoogle = new Provider(config)
  const signinOptions = options || {}
  signinOptions.signin_uri = 'https://accounts.google.com/o/oauth2/v2/auth'
  signinOptions.scope = 'profile email'
  signinOptions.response_type = 'code'
  return customGoogle.signin(signinOptions)
}

const callbackHandler = async (event, config) => {
  const customGoogle = new Provider(config)
  const profileMap = (response) =>
    new Profile({
      id: response.id,
      name: response.displayName,
      email: response.emails ? response.emails[0].value : null,
      picture: response.image ? response.image.url : null,
      provider: 'custom-google',
      at: response.access_token
    })

  const options = {
    authorization_uri: 'https://www.googleapis.com/oauth2/v4/token',
    profile_uri: 'https://www.googleapis.com/plus/v1/people/me',
    profileMap
  }

  return customGoogle.callback(event, options, {
    authorization: { grant_type: 'authorization_code' }
  })
}

module.exports = {
  signinHandler,
  callbackHandler
}
