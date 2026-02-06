/**
 * Created by eetut on 23/11/2016.
 */
'use strict'

const _ = require('lodash')
const chalk = require('chalk')

class Deploy {
  constructor(serverless, options) {
    this.serverless = serverless
    this.options = options
    this.provider = this.serverless.providers.aws
    this.commands = {
      authentication: {
        commands: {
          info: {
            usage: 'Get info',
            lifecycleEvents: ['info']
          }
        }
      }
    }

    this.hooks = {
      'authentication:info:info': this.info.bind(this),
      'after:info:info': this.info.bind(this),
      'after:deploy:deploy': this.info.bind(this)
    }
  }

  info() {
    const providers = _(this.serverless.service.provider.environment)
      .keys()
      .filter(key => /PROVIDER_.+_ID/.test(key))
      .map(provider =>
        provider
          .replace(/PROVIDER_/, '')
          .replace(/_ID/, '')
          .replace(/_/, '-')
          .toLowerCase()
      )
      .value()
    //
    const stackName = this.provider.naming.getStackName(this.options.stage)

    return this.provider
      .request(
        'CloudFormation',
        'describeStacks',
        { StackName: stackName },
        this.options.stage,
        this.options.region
      )
      .then(result => {
        const stack = _.first(result.Stacks)
        let authorizerFunction = _(stack.Outputs).find({
          OutputKey: 'AuthorizeLambdaFunctionQualifiedArn'
        }).OutputValue

        if (this.serverless.service.provider.versionFunctions) {
          authorizerFunction = authorizerFunction.substr(
            0,
            authorizerFunction.lastIndexOf(':')
          )
        }

        const serviceEndpoint = _.find(stack.Outputs, {
          OutputKey: 'ServiceEndpoint'
        }).OutputValue
        return { authorizerFunction, serviceEndpoint }
      })
      .then(resources => {
        const domain = this.serverless.service.provider.environment
          .REDIRECT_DOMAIN_NAME
          ? `https://${
              this.serverless.service.provider.environment.REDIRECT_DOMAIN_NAME
            }`
          : resources.serviceEndpoint
        let message = ''
        message += `${chalk.yellow.underline(
          '\nAuthentication Service Information'
        )}\n`
        message += `${chalk.yellow('Authorizer function:')} ${
          resources.authorizerFunction
        }\n`
        message += `${chalk.yellow('Signin endpoints:\n')}`
        message += providers
          .map(provider => {
            return `${domain}/authentication/signin/${provider}`
          })
          .join('\n')
        message += `\n${chalk.yellow('Callback endpoints:\n')}`
        message += providers
          .map(provider => {
            return `${domain}/authentication/callback/${provider}`
          })
          .join('\n')
        this.serverless.cli.consoleLog(message)
      })
  }
}

module.exports = Deploy
