/**
 * @name AWS Resource Parameter Value Tracking
 * @description Tracks data flow from various sources to AWS service resource parameters
 * @kind table
 * @id javascript/aws-resource-value-tracking
 */

import javascript
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking

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
 * AWS SDK v3 service names from package names
 */
bindingset[packageName]
string getServiceFromV3Package(string packageName) {
  packageName.matches("@aws-sdk/client-%") and
  result = packageName.regexpCapture("@aws-sdk/client-([a-z0-9-]+)", 1)
}

/**
 * AWS SDK v3 action names from Command class names
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
          clientSource.asExpr() = client
          or
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
}

/**
 * Identifies AWS SDK v3 Command instantiations
 */
class AwsSdkV3CommandInstantiation extends NewExpr {
  string actionName;
  string serviceName;

  AwsSdkV3CommandInstantiation() {
    exists(string className |
      className = this.getCallee().(VarAccess).getName() and
      className.matches("%Command") and
      actionName = getActionFromCommandClass(className) and
      (
        exists(ImportDeclaration imp, string pkgName |
          pkgName = imp.getImportedPathString() and
          pkgName.matches("@aws-sdk/client-%") and
          serviceName = getServiceFromV3Package(pkgName)
        )
        or
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
}

/**
 * Helper predicate to get the ObjectExpr from an argument (inline or via variable)
 */
ObjectExpr getParamsObjectFromArg(Expr arg) {
  // Direct inline object
  result = arg
  or
  // Variable reference: const params = {...}; method(params)
  exists(VarAccess va, Variable v |
    va = arg and
    v = va.getVariable() and
    result = v.getAnAssignedExpr()
  )
}

/**
 * A sink representing an AWS resource parameter property assignment
 */
class AwsResourceParameterSink extends DataFlow::Node {
  string parameterName;
  string actionName;

  AwsResourceParameterSink() {
    exists(Property prop, ObjectExpr params |
      isAwsResourceParameter(parameterName) and
      prop.getName() = parameterName and
      prop = params.getAProperty() and
      this.asExpr() = prop.getInit() and
      (
        // AWS SDK v2: method call with object argument (inline or variable)
        exists(AwsSdkV2MethodCall call |
          params = getParamsObjectFromArg(call.getArgument(0)) and
          actionName = call.getActionName()
        )
        or
        // AWS SDK v3: Command constructor with object argument (inline or variable)
        exists(AwsSdkV3CommandInstantiation cmd |
          params = getParamsObjectFromArg(cmd.getArgument(0)) and
          actionName = cmd.getActionName()
        )
      )
    )
  }

  string getParameterName() { result = parameterName }
  string getActionName() { result = actionName }
}

/**
 * Configuration for tracking values to AWS resource parameters
 */
module AwsResourceValueConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // String literals
    source.asExpr() instanceof StringLiteral
    or
    // Number literals (for numeric IDs)
    source.asExpr() instanceof NumberLiteral
    or
    // Template literals
    source.asExpr() instanceof TemplateLiteral
    or
    // Environment variables: process.env.VAR_NAME
    exists(PropAccess pa |
      pa = source.asExpr() and
      pa.getBase().(PropAccess).getBase().(VarAccess).getName() = "process" and
      pa.getBase().(PropAccess).getPropertyName() = "env"
    )
    or
    // Environment variable access via bracket notation: process.env["VAR_NAME"]
    exists(IndexExpr ie |
      ie = source.asExpr() and
      ie.getBase().(PropAccess).getBase().(VarAccess).getName() = "process" and
      ie.getBase().(PropAccess).getPropertyName() = "env"
    )
    or
    // Function parameters
    exists(Parameter p | source = DataFlow::parameterNode(p))
    or
    // Module-level variable declarations (potential constants)
    exists(VariableDeclarator vd, TopLevel tl |
      vd.getBindingPattern() = source.asExpr() and
      vd.getEnclosingStmt().getContainer() = tl
    )
    or
    // Require calls (for config files)
    exists(CallExpr ce |
      ce = source.asExpr() and
      ce.getCalleeName() = "require"
    )
    or
    // Property access on imported modules/objects
    exists(PropAccess pa |
      pa = source.asExpr() and
      not pa.getBase().(PropAccess).getBase().(VarAccess).getName() = "process"
    )
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof AwsResourceParameterSink
  }
}

module AwsResourceFlow = TaintTracking::Global<AwsResourceValueConfig>;

/**
 * Classify the source type
 */
string getSourceType(DataFlow::Node source) {
  source.asExpr() instanceof StringLiteral and result = "LITERAL"
  or
  source.asExpr() instanceof NumberLiteral and result = "LITERAL"
  or
  source.asExpr() instanceof TemplateLiteral and result = "TEMPLATE_LITERAL"
  or
  exists(PropAccess pa |
    pa = source.asExpr() and
    pa.getBase().(PropAccess).getBase().(VarAccess).getName() = "process" and
    pa.getBase().(PropAccess).getPropertyName() = "env" and
    result = "ENV_VAR"
  )
  or
  exists(IndexExpr ie |
    ie = source.asExpr() and
    ie.getBase().(PropAccess).getBase().(VarAccess).getName() = "process" and
    ie.getBase().(PropAccess).getPropertyName() = "env" and
    result = "ENV_VAR"
  )
  or
  exists(Parameter p |
    source = DataFlow::parameterNode(p) and
    result = "PARAMETER"
  )
  or
  exists(CallExpr ce |
    ce = source.asExpr() and
    ce.getCalleeName() = "require" and
    result = "REQUIRE"
  )
  or
  // Default for other cases
  not source.asExpr() instanceof StringLiteral and
  not source.asExpr() instanceof NumberLiteral and
  not source.asExpr() instanceof TemplateLiteral and
  not exists(PropAccess pa |
    pa = source.asExpr() and
    pa.getBase().(PropAccess).getBase().(VarAccess).getName() = "process"
  ) and
  not exists(IndexExpr ie |
    ie = source.asExpr() and
    ie.getBase().(PropAccess).getBase().(VarAccess).getName() = "process"
  ) and
  not exists(Parameter p | source = DataFlow::parameterNode(p)) and
  not exists(CallExpr ce | ce = source.asExpr() and ce.getCalleeName() = "require") and
  result = "VARIABLE"
}

/**
 * Get detailed source information
 */
string getSourceDetail(DataFlow::Node source) {
  // String literal - get full value
  result = source.asExpr().(StringLiteral).getValue()
  or
  // Number literal
  result = source.asExpr().(NumberLiteral).getValue().toString()
  or
  // Template literal - construct full representation
  exists(TemplateLiteral tl |
    source.asExpr() = tl and
    result = concat(int i | | tl.getElement(i).toString(), "" order by i)
  )
  or
  // Environment variable via dot notation: process.env.VAR_NAME
  exists(PropAccess pa |
    pa = source.asExpr() and
    pa.getBase().(PropAccess).getBase().(VarAccess).getName() = "process" and
    pa.getBase().(PropAccess).getPropertyName() = "env" and
    result = "env:" + pa.getPropertyName()
  )
  or
  // Environment variable via bracket notation: process.env["VAR_NAME"]
  exists(IndexExpr ie |
    ie = source.asExpr() and
    ie.getBase().(PropAccess).getBase().(VarAccess).getName() = "process" and
    ie.getBase().(PropAccess).getPropertyName() = "env" and
    result = "env:" + ie.getIndex().(StringLiteral).getValue()
  )
  or
  // Function parameter - find the function that declares this parameter
  exists(Parameter p, Function f |
    source = DataFlow::parameterNode(p) and
    f.getAParameter() = p and
    result = f.getName() + ":" + p.getName()
  )
  or
  // Require call
  exists(CallExpr ce |
    ce = source.asExpr() and
    ce.getCalleeName() = "require" and
    result = "require:" + ce.getArgument(0).(StringLiteral).getValue()
  )
  or
  // Fallback - use expression string representation with file location
  not source.asExpr() instanceof StringLiteral and
  not source.asExpr() instanceof NumberLiteral and
  not source.asExpr() instanceof TemplateLiteral and
  not exists(PropAccess pa |
    pa = source.asExpr() and
    pa.getBase().(PropAccess).getBase().(VarAccess).getName() = "process"
  ) and
  not exists(IndexExpr ie |
    ie = source.asExpr() and
    ie.getBase().(PropAccess).getBase().(VarAccess).getName() = "process"
  ) and
  not exists(Parameter p | source = DataFlow::parameterNode(p)) and
  not exists(CallExpr ce | ce = source.asExpr() and ce.getCalleeName() = "require") and
  result = "var:" + source.asExpr().toString()
}

from
  AwsResourceFlow::PathNode source,
  AwsResourceFlow::PathNode sink,
  AwsResourceParameterSink sinkNode,
  string sourceType,
  string sourceDetail
where
  AwsResourceFlow::flowPath(source, sink) and
  sinkNode = sink.getNode() and
  sourceType = getSourceType(source.getNode()) and
  sourceDetail = getSourceDetail(source.getNode())
select
  sink.getNode().getLocation() as path,
  sinkNode.getActionName() as serviceAction,
  sinkNode.getParameterName() as resourceName,
  sourceDetail as resourceValue,
  sourceType as valueSource
