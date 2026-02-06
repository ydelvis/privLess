const AWS = require('aws-sdk')

const config = {
  region: process.env.REGION || 'eu-west-1'
}

const dynamodb = new AWS.DynamoDB.DocumentClient(config)
const crypto = require('crypto')
const Promise = require('bluebird')

function hash() {
  return crypto.randomBytes(48).toString('hex')
}

/**
 * Creates OAuth State
 */
const createState = async () => {
  const state = hash()
  const params = {
    TableName: process.env.CACHE_DB_NAME,
    Item: {
      token: state,
      type: 'STATE',
      expired: false
    }
  }

  return dynamodb
    .put(params).promise()
    .then(() => state)
}

/**
 * Revokes OAuth State
 * @param state
 */
const revokeState = async (state) => new Promise((resolve, reject) => {
  const queryToken = async () => {
    const params = {
      TableName: process.env.CACHE_DB_NAME,
      ProjectionExpression: '#token, #type, Expired',
      KeyConditionExpression: '#token = :token and #type = :type',
      ExpressionAttributeNames: {
        '#token': 'token',
        '#type': 'type'
      },
      ExpressionAttributeValues: {
        ':token': state,
        ':type': 'STATE'
      }
    }

    return dynamodb
      .query(params).promise()
  }

  const insertToken = async (data) => {
    const item = data.Items[0]
    if (item.expired) {
      throw new Error('State expired')
    } else {
      const params = {
        TableName: process.env.CACHE_DB_NAME,
        Item: {
          token: state,
          type: 'STATE',
          expired: true
        }
      }

      return dynamodb
        .put(params).promise()
        .then(() => item.token)
    }
  }

  queryToken()
    .then(insertToken)
    .then((token) => {
      if (state !== token) {
        reject(new Error('State mismatch'))
      }
      resolve(token)
    })
    .catch(reject)
})

/**
 * Creates and saves refresh token
 * @param user
 */
const saveRefreshToken = async (user, payload) => {
  const token = hash()
  const params = {
    TableName: process.env.CACHE_DB_NAME,
    Item: {
      token,
      type: 'REFRESH',
      expired: false,
      userId: user,
      payload: JSON.stringify(payload || {})
    }
  }

  return dynamodb
    .put(params).promise()
    .then(() => token)
}

/**
 * Revokes old refresh token and creates new
 * @param oldToken
 */
const revokeRefreshToken = async (oldToken) => new Promise((resolve, reject) => {
  if (oldToken.match(/[A-Fa-f0-9]{64}/)) {
    const token = hash()

    const queryToken = () => {
      const params = {
        TableName: process.env.CACHE_DB_NAME,
        ProjectionExpression: '#token, #type, #userId',
        KeyConditionExpression: '#token = :token and #type = :type',
        ExpressionAttributeNames: {
          '#token': 'token',
          '#type': 'type',
          '#userId': 'userId'
        },
        ExpressionAttributeValues: {
          ':token': oldToken,
          ':type': 'REFRESH'
        }
      }

      return dynamodb
        .query(params).promise()
    }

    const newRefreshToken = async (data) => {
      const { userId, payload } = data.Items[0]

      const params = {
        TableName: process.env.CACHE_DB_NAME,
        Item: {
          token,
          type: 'REFRESH',
          expired: false,
          userId,
          payload
        }
      }

      return dynamodb
        .put(params).promise()
        .then(() => userId)
    }

    const expireRefreshToken = async (userId) => {
      const params = {
        TableName: process.env.CACHE_DB_NAME,
        Item: {
          token: oldToken,
          type: 'REFRESH',
          expired: true,
          userId
        }
      }

      return dynamodb
        .put(params).promise()
        .then(() => userId)
    }

    queryToken().then((data) =>
      newRefreshToken(data)
        .then(expireRefreshToken)
        .then((id) => resolve({
          id,
          token,
          payload: data.payload && JSON.parse(data.payload)
        })))
      .catch(reject)
  } else {
    reject(new Error('Invalid token'))
  }
})

module.exports = {
  createState,
  revokeState,
  saveRefreshToken,
  revokeRefreshToken
}
