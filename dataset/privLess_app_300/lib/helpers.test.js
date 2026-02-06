const helpers = require('./helpers')

describe('helpers', () => {
  it('should create response data', () => {
    const data = helpers.createResponseData('id')
    expect(data).toEqual({
      authorizationToken: { options: { expiresIn: 15 }, payload: { id: 'id' } }
    })
  })
})
