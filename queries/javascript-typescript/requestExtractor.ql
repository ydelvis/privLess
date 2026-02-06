/**
 * @name Detect AWS SDK for JavaScript/TypeScript Calls with Arguments
 * @description Identifies all AWS SDK for JavaScript/TypeScript service calls
 * @kind table
 * @id javascript/detect-aws-sdk-calls-with-args
 */

import javascript

/**
 * AWS resource parameter property names across key services
 */
predicate isAwsResourceParameter(string propName) {
  propName in [
    "Bucket", "Key",  // S3 Bucket and Object Key
    "FunctionName",  // Lambda Function Name
    "QueueName", "QueueUrl", // SQS Queue Name
    "TopicName", "TopicArn", "TargetArn", "SubscriptionArn", // SNS Topic Name
    "TableName", // DynamoDB Table Name
    "StateMachineName", "StateMachineArn", // Step Functions State Machine Name
    "DomainName", // AppSync, Route53 Domain Name
    "StreamName", "StreamArn", // Kinesis Stream Name
    "ClusterName", "Cluster", "ClusterResourceId", // ECS Cluster Name
    "DBInstanceIdentifier", "DBClusterIdentifier", // RDS Instance Identifier
    "AccessPointId", // EFS Access Point Name
    "LogGroupName", "MetricName", "Namespace", // CloudWatch Log Group Name
    "AppId", "ApplicationId", // Pinpoint Application ID
    "ThingName", "ThingGroupName", "StreamId", // IoT Thing and Thing Group Names
    "ApiId", // AppSync
    "SecretId", // Secrets Manager
    "ParameterName", // SSM Parameter Store
    "IdentityPoolId", "UserPoolId", // Cognito
    "DistributionId", // CloudFront
    "HostedZoneId", // Route53
    "CertificateArn", // ACM
    "RoleArn", "PolicyArn", "UserName", "GroupName" // IAM
  ]
}

/**
 * AWS SDK v3 service names mapped from package names
 * @aws-sdk/client-s3 -> s3
 */
bindingset[packageName]
string getServiceFromV3Package(string packageName) {
  packageName.matches("@aws-sdk/client-%") and
  result = packageName.regexpCapture("@aws-sdk/client-([a-z0-9-]+)", 1)
}

/**
 * AWS SDK v3 action names from Command class names
 * GetObjectCommand -> GetObject
 */
bindingset[className]
string getActionFromCommandClass(string className) {
  className.matches("%Command") and
  result = className.regexpCapture("([A-Za-z0-9]+)Command", 1)
}

/**
 * Heuristic to get service name from variable name
 */
bindingset[varName]
string getServiceFromVarName(string varName) {
  varName.regexpMatch("(?i).*s3.*|.*bucket.*") and result = "S3"
  or
  varName.regexpMatch("(?i).*lambda.*") and result = "Lambda"
  or
  varName.regexpMatch("(?i).*dynamo.*|.*ddb.*|.*documentclient.*") and result = "DynamoDB"
  or
  varName.regexpMatch("(?i).*sqs.*|.*queue.*") and result = "SQS"
  or
  varName.regexpMatch("(?i).*sns.*|.*topic.*") and result = "SNS"
  or
  varName.regexpMatch("(?i).*kinesis.*|.*stream.*") and result = "Kinesis"
  or
  varName.regexpMatch("(?i).*ecs.*|.*cluster.*") and result = "ECS"
  or
  varName.regexpMatch("(?i).*rds.*|.*database.*") and result = "RDS"
  or
  varName.regexpMatch("(?i).*secretsmanager.*|.*secrets.*") and result = "SecretsManager"
  or
  varName.regexpMatch("(?i).*ssm.*|.*parameter.*") and result = "SSM"
  or
  varName.regexpMatch("(?i).*cognito.*") and result = "Cognito"
  or
  varName.regexpMatch("(?i).*cloudfront.*|.*cf.*") and result = "CloudFront"
  or
  varName.regexpMatch("(?i).*route53.*|.*r53.*") and result = "Route53"
  or
  varName.regexpMatch("(?i).*iam.*") and result = "IAM"
  or
  varName.regexpMatch("(?i).*acm.*|.*certificate.*") and result = "ACM"
  or
  varName.regexpMatch("(?i).*cloudwatch.*|.*cw.*|.*logs.*") and result = "CloudWatch"
  or
  varName.regexpMatch("(?i).*stepfunctions.*|.*sfn.*|.*statemachine.*") and result = "StepFunctions"
  or
  varName.regexpMatch("(?i).*iot.*") and result = "IoT"
  or
  varName.regexpMatch("(?i).*appsync.*|.*graphql.*") and result = "AppSync"
  or
  varName.regexpMatch("(?i).*pinpoint.*") and result = "Pinpoint"
  or
  varName.regexpMatch("(?i).*efs.*") and result = "EFS"
}

/**
 * Checks if an expression is rooted at the AWS namespace
 * Handles: AWS.S3, AWS.DynamoDB, AWS.DynamoDB.DocumentClient, etc.
 */
predicate isAwsNamespaceAccess(Expr e) {
  e.(VarAccess).getName() = "AWS"
  or
  isAwsNamespaceAccess(e.(PropAccess).getBase())
}

/**
 * Gets the service name from an AWS SDK v2 instantiation expression
 * Handles both simple (AWS.S3) and nested (AWS.DynamoDB.DocumentClient) patterns
 */
string getAwsServiceFromExpr(Expr e) {
  // Simple case: AWS.S3 -> S3
  exists(PropAccess pa |
    pa = e and
    pa.getBase().(VarAccess).getName() = "AWS" and
    result = pa.getPropertyName()
  )
  or
  // Nested case: AWS.DynamoDB.DocumentClient -> DynamoDB
  exists(PropAccess pa, PropAccess inner |
    pa = e and
    inner = pa.getBase() and
    inner.getBase().(VarAccess).getName() = "AWS" and
    result = inner.getPropertyName()
  )
  or
  // Deeper nested: AWS.Service.Sub.Client -> Service
  exists(PropAccess pa |
    pa = e and
    isAwsNamespaceAccess(pa.getBase()) and
    not pa.getBase().(VarAccess).getName() = "AWS" and
    // Get the first property after AWS
    exists(PropAccess firstProp |
      firstProp.getBase().(VarAccess).getName() = "AWS" and
      firstProp.getParentExpr+() = pa and
      result = firstProp.getPropertyName()
    )
  )
}

/**
 * Identifies AWS SDK v2 service client instantiations
 * Handles: new AWS.S3(), new AWS.DynamoDB.DocumentClient(), etc.
 */
class AwsSdkV2ClientInstantiation extends NewExpr {
  string serviceName;

  AwsSdkV2ClientInstantiation() {
    exists(Expr callee |
      callee = this.getCallee() and
      isAwsNamespaceAccess(callee) and
      serviceName = getAwsServiceFromExpr(callee)
    )
  }

  string getServiceName() { result = serviceName }
}

/**
 * Identifies AWS SDK v2 method calls
 * e.g., s3.getObject({...}), lambda.invoke({...})
 */
class AwsSdkV2MethodCall extends MethodCallExpr {
  string serviceName;
  string methodName;

  AwsSdkV2MethodCall() {
    // Always bind methodName first
    methodName = this.getMethodName() and
    (
      // Find the receiver's type through data flow from AWS.ServiceName constructor
      exists(AwsSdkV2ClientInstantiation client, DataFlow::SourceNode clientSource |
        clientSource.getALocalUse().asExpr() = this.getReceiver() and
        (
          // Direct: new AWS.S3().getObject(...)
          clientSource.asExpr() = client
          or
          // Variable: const s3 = new AWS.S3(); s3.getObject(...)
          exists(Variable v |
            v.getAnAssignedExpr() = client and
            clientSource = DataFlow::valueNode(v.getAnAccess())
          )
        ) and
        serviceName = client.getServiceName()
      )
      or
      // Heuristic: common AWS service method patterns when we can't trace the client
      exists(string receiver |
        receiver = this.getReceiver().(VarAccess).getName() and
        serviceName = getServiceFromVarName(receiver)
      )
    )
  }

  string getServiceName() { result = serviceName }
  string getActionName() { result = methodName }

  /** Gets the params argument (may be ObjectExpr or VarAccess) */
  Expr getParamsArg() {
    result = this.getArgument(0)
  }

  /** Gets the ObjectExpr for params, resolving through variables if needed */
  ObjectExpr getParamsObject() {
    // Direct inline object: dynamo.put({ TableName: ... })
    result = this.getArgument(0)
    or
    // Variable reference: const params = {...}; dynamo.put(params)
    exists(VarAccess va, Variable v |
      va = this.getArgument(0) and
      v = va.getVariable() and
      result = v.getAnAssignedExpr()
    )
  }
}

/**
 * Identifies AWS SDK v3 Command instantiations
 * e.g., new GetObjectCommand({...})
 */
class AwsSdkV3CommandInstantiation extends NewExpr {
  string actionName;
  string serviceName;

  AwsSdkV3CommandInstantiation() {
    exists(string className |
      className = this.getCallee().(VarAccess).getName() and
      className.matches("%Command") and
      actionName = getActionFromCommandClass(className) and
      // Try to find service from imports
      (
        exists(ImportDeclaration imp, string pkgName |
          pkgName = imp.getImportedPathString() and
          pkgName.matches("@aws-sdk/client-%") and
          serviceName = getServiceFromV3Package(pkgName)
        )
        or
        // Heuristic based on command name prefixes
        (
          actionName.regexpMatch("(?i).*object.*|.*bucket.*") and serviceName = "s3"
          or
          actionName.regexpMatch("(?i).*function.*|.*invoke.*") and serviceName = "lambda"
          or
          actionName.regexpMatch("(?i).*table.*|.*item.*") and serviceName = "dynamodb"
          or
          actionName.regexpMatch("(?i).*queue.*|.*message.*") and serviceName = "sqs"
          or
          actionName.regexpMatch("(?i).*topic.*|.*publish.*|.*subscribe.*") and serviceName = "sns"
          or
          not actionName.regexpMatch("(?i).*object.*|.*bucket.*|.*function.*|.*invoke.*|.*table.*|.*item.*|.*queue.*|.*message.*|.*topic.*|.*publish.*|.*subscribe.*") and
          serviceName = "unknown"
        )
      )
    )
  }

  string getActionName() { result = actionName }
  string getServiceName() { result = serviceName }

  /** Gets the params argument (may be ObjectExpr or VarAccess) */
  Expr getParamsArg() {
    result = this.getArgument(0)
  }

  /** Gets the ObjectExpr for params, resolving through variables if needed */
  ObjectExpr getParamsObject() {
    // Direct inline object: new GetObjectCommand({ Bucket: ... })
    result = this.getArgument(0)
    or
    // Variable reference: const params = {...}; new GetObjectCommand(params)
    exists(VarAccess va, Variable v |
      va = this.getArgument(0) and
      v = va.getVariable() and
      result = v.getAnAssignedExpr()
    )
  }
}

/**
 * Gets the full string value from various expression types
 * Handles: string literals, template literals, concatenation, etc.
 */
string getStringValue(Expr e) {
  // String literal
  result = e.(StringLiteral).getValue()
  or
  // Number literal (converted to string)
  result = e.(NumberLiteral).getValue().toString()
  or
  // Template literal without substitutions
  e instanceof TemplateLiteral and
  not exists(e.(TemplateLiteral).getAnElement().(TemplateElement).getRawValue()) and
  result = e.toString()
  or
  // Template literal - get raw value
  exists(TemplateLiteral tl |
    e = tl and
    result = concat(int i | | tl.getElement(i).toString(), "" order by i)
  )
  or
  // Variable access - return variable name
  result = "${" + e.(VarAccess).getName() + "}"
  or
  // Property access (e.g., process.env.BUCKET)
  exists(PropAccess pa |
    e = pa and
    result = "${" + pa.getPropertyName() + "}"
  )
  or
  // Addition/concatenation - try to resolve
  exists(AddExpr add |
    e = add and
    result = getStringValue(add.getLeftOperand()) + getStringValue(add.getRightOperand())
  )
  or
  // Call expression - indicate it's a function call
  exists(CallExpr call |
    e = call and
    result = "${" + call.getCalleeName() + "(...)}"
  )
  or
  // Fallback - use toString with location info
  not e instanceof StringLiteral and
  not e instanceof NumberLiteral and
  not e instanceof TemplateLiteral and
  not e instanceof VarAccess and
  not e instanceof PropAccess and
  not e instanceof AddExpr and
  not e instanceof CallExpr and
  result = e.toString()
}

/**
 * Predicate to extract AWS SDK v2 resource parameters
 */
predicate awsSdkV2ResourceParam(
  AwsSdkV2MethodCall methodCall,
  string service,
  string action,
  string resourceName,
  string resourceValue
) {
  service = methodCall.getServiceName() and
  action = methodCall.getActionName() and
  exists(ObjectExpr params, Property prop |
    params = methodCall.getParamsObject() and
    prop = params.getAProperty() and
    resourceName = prop.getName() and
    isAwsResourceParameter(resourceName) and
    resourceValue = getStringValue(prop.getInit())
  )
}

/**
 * Predicate to extract AWS SDK v3 resource parameters
 */
predicate awsSdkV3ResourceParam(
  AwsSdkV3CommandInstantiation command,
  string service,
  string action,
  string resourceName,
  string resourceValue
) {
  service = command.getServiceName() and
  action = command.getActionName() and
  exists(ObjectExpr params, Property prop |
    params = command.getParamsObject() and
    prop = params.getAProperty() and
    isAwsResourceParameter(prop.getName()) and
    resourceName = prop.getName() and
    resourceValue = getStringValue(prop.getInit())
  )
}

/**
 * Combined query for both AWS SDK v2 and v3 resource parameters
 */
from string path, string service, string serviceAction, string resourceName, string resourceValue
where
  // AWS SDK v2 calls
  exists(AwsSdkV2MethodCall methodCall |
    awsSdkV2ResourceParam(methodCall, service, serviceAction, resourceName, resourceValue) and
    path = methodCall.getLocation().toString()
  )
  or
  // AWS SDK v3 calls
  exists(AwsSdkV3CommandInstantiation command |
    awsSdkV3ResourceParam(command, service, serviceAction, resourceName, resourceValue) and
    path = command.getLocation().toString()
  )
select path, service, serviceAction, resourceName, resourceValue
