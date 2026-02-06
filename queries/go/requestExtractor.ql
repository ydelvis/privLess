/**
 * @name Detect AWS SDK for Go Calls with Arguments
 * @description Identifies all AWS SDK for Go service calls
 * @kind table
 * @id go/detect-aws-sdk-calls-with-args
 */

import go

/**
 * Matches AWS SDK for Go service packages (both v1 and v2)
 * v1: github.com/aws/aws-sdk-go/service/<service>
 * v2: github.com/aws/aws-sdk-go-v2/service/<service>
 */
bindingset[packagePath]
predicate isAwsSdkServicePackage(string packagePath, string service) {
  (
    packagePath.matches("github.com/aws/aws-sdk-go/service/%") or
    packagePath.matches("github.com/aws/aws-sdk-go-v2/service/%")
  ) and
  service = packagePath.regexpCapture("github.com/aws/aws-sdk-go(?:-v2)?/service/([^/]+)(?:/.*)?", 1)
}

/**
 * AWS resource parameter field names across key services
 */
predicate isAwsResourceParameter(string fieldName) {
  fieldName in [
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
    "ApiId" // AppSync
  ]
}

/**
 * Gets an AWS SDK method call (a method call on an AWS service client)
 */
class AwsSdkMethodCall extends DataFlow::CallNode {
  string service;
  string methodName;

  AwsSdkMethodCall() {
    exists(Method m, string packagePath |
      this = m.getACall() and
      packagePath = m.getReceiverType().getPackage().getPath() and
      isAwsSdkServicePackage(packagePath, service) and
      methodName = m.getName() and
      // Filter out constructor and utility methods
      not methodName.matches("New%") and
      not methodName in ["Options", "WithContext"]
    )
  }

  string getService() { result = service }
  string getMethodName() { result = methodName }
}

/**
 * Gets the string value from an aws.String() call or similar pointer wrapper
 */
string getAwsStringValue(DataFlow::Node node) {
  // Direct string literal wrapped in aws.String()
  exists(DataFlow::CallNode call, StringLit lit |
    call = node and
    call.getTarget().getName() = "String" and
    call.getTarget().getPackage().getPath().matches("%/aws") and
    lit = call.getArgument(0).asExpr() and
    result = lit.getValue()
  )
  or
  // Direct string literal
  exists(StringLit lit |
    lit = node.asExpr() and
    result = lit.getValue()
  )
  or
  // Variable or expression - return string representation
  not exists(StringLit lit | lit = node.asExpr()) and
  not exists(DataFlow::CallNode call |
    call = node and
    call.getTarget().getName() = "String" and
    call.getTarget().getPackage().getPath().matches("%/aws")
  ) and
  result = node.asExpr().toString()
}

/**
 * Struct literal key-value pair representing a resource parameter
 */
class ResourceParameterAssignment extends KeyValueExpr {
  string fieldName;
  AwsSdkMethodCall methodCall;

  ResourceParameterAssignment() {
    isAwsResourceParameter(fieldName) and
    fieldName = this.getKey().(Ident).getName() and
    // This struct literal is an argument to an AWS SDK method call
    exists(CompositeLit structLit |
      this = structLit.getAnElement() and
      (
        // Direct argument: client.Method(&Input{...})
        methodCall.getAnArgument().asExpr().(UnaryExpr).getOperand() = structLit
        or
        // Direct argument without address-of: client.Method(Input{...})
        methodCall.getAnArgument().asExpr() = structLit
      )
    )
  }

  string getFieldName() { result = fieldName }
  AwsSdkMethodCall getMethodCall() { result = methodCall }
  Expr getValueExpr() { result = this.getValue() }
}

from
  AwsSdkMethodCall methodCall,
  string service,
  string serviceAction,
  string resourceName,
  string resourceValue,
  ResourceParameterAssignment param
where
  methodCall = param.getMethodCall() and
  service = methodCall.getService() and
  serviceAction = methodCall.getMethodName() and
  resourceName = param.getFieldName() and
  resourceValue = getAwsStringValue(DataFlow::exprNode(param.getValueExpr()))
select
  methodCall.getLocation() as path,
  service,
  serviceAction,
  resourceName,
  resourceValue
