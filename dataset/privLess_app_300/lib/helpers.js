const logger = require('log4js').getLogger()

const createResponseData = (id) => {
  // sets 15 seconds expiration time as an example
  const authorizationToken = {
    payload: {
      id
    },
    options: {
      expiresIn: 15
    }
  }

  return { authorizationToken }
}

const log = (message) => {
  logger.debug(message)
}

module.exports = {
  createResponseData,
  log
}
