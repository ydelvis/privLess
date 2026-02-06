
import json


class ViewUser:

  def __init__(self, repo, requestParams, requestBody, pathParams):
    self.repo = repo
    self.requestParams = requestParams
    self.requestBody = requestBody
    self.pathParams = pathParams

  def execute(self):
    resp = self.repo.get_user(self.pathParams['id'])
    return {
      'statusCode' : 200,
      'body' : json.dumps(resp)
    }




