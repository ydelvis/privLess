/**
 * @name AWS Resource Parameter Value Tracking
 * @description Tracks data flow from various sources to AWS service resource parameters
 * @kind table
 * @id go/aws-resource-value-tracking
 */

import go
import semmle.go.dataflow.TaintTracking

/**
 * Matches AWS SDK for Go service packages (both v1 and v2)
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
      not methodName.matches("New%") and
      not methodName in ["Options", "WithContext"]
    )
  }

  string getService() { result = service }
  string getMethodName() { result = methodName }
}

/**
 * A sink that represents an AWS resource parameter value assignment
 */
class AwsResourceParameterSink extends DataFlow::Node {
  string parameterName;
  AwsSdkMethodCall methodCall;

  AwsResourceParameterSink() {
    exists(KeyValueExpr kv, CompositeLit structLit |
      isAwsResourceParameter(parameterName) and
      parameterName = kv.getKey().(Ident).getName() and
      kv = structLit.getAnElement() and
      (
        // Value is passed to aws.String() wrapper
        exists(DataFlow::CallNode awsStringCall |
          awsStringCall.getTarget().getName() = "String" and
          awsStringCall.getTarget().getPackage().getPath().matches("%/aws") and
          awsStringCall.asExpr() = kv.getValue() and
          this = awsStringCall.getArgument(0)
        )
        or
        // Direct value assignment (no aws.String wrapper)
        not exists(DataFlow::CallNode awsStringCall |
          awsStringCall.getTarget().getName() = "String" and
          awsStringCall.getTarget().getPackage().getPath().matches("%/aws") and
          awsStringCall.asExpr() = kv.getValue()
        ) and
        this.asExpr() = kv.getValue()
      ) and
      // Struct is argument to AWS SDK method
      (
        methodCall.getAnArgument().asExpr().(UnaryExpr).getOperand() = structLit or
        methodCall.getAnArgument().asExpr() = structLit
      )
    )
  }

  string getParameterName() { result = parameterName }

  string getAwsMethodName() { result = methodCall.getMethodName() }
}

/**
 * Configuration for tracking values to AWS resource parameters
 */
module AwsResourceValueConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // String literals
    source.asExpr() instanceof StringLit
    or
    // Environment variables - os.Getenv("KEY")
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("os", "Getenv") and
      source = call
    )
    or
    // Environment variables - os.LookupEnv("KEY")
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("os", "LookupEnv") and
      source = call.getResult(0)
    )
    or
    // Function parameters
    exists(Parameter p | source = DataFlow::parameterNode(p))
    or
    // Package-level (global) variable reads
    exists(Variable v |
      v.getScope() instanceof PackageScope and
      source = v.getARead()
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
  source.asExpr() instanceof StringLit and result = "LITERAL"
  or
  exists(DataFlow::CallNode call |
    call.getTarget().hasQualifiedName("os", "Getenv") and
    source = call and
    result = "ENV_VAR"
  )
  or
  exists(DataFlow::CallNode call |
    call.getTarget().hasQualifiedName("os", "LookupEnv") and
    source = call.getResult(0) and
    result = "ENV_VAR"
  )
  or
  exists(Parameter p |
    source = DataFlow::parameterNode(p) and
    result = "PARAMETER"
  )
  or
  exists(Variable v |
    v.getScope() instanceof PackageScope and
    source = v.getARead() and
    result = "GLOBAL_VAR"
  )
}

/**
 * Get source detail information
 */
string getSourceDetail(DataFlow::Node source) {
  // String literal value
  result = source.asExpr().(StringLit).getValue()
  or
  // Environment variable from os.Getenv
  exists(DataFlow::CallNode call, StringLit envKey |
    call.getTarget().hasQualifiedName("os", "Getenv") and
    source = call and
    envKey = call.getArgument(0).asExpr() and
    result = "env:" + envKey.getValue()
  )
  or
  // Environment variable from os.LookupEnv
  exists(DataFlow::CallNode call, StringLit envKey |
    call.getTarget().hasQualifiedName("os", "LookupEnv") and
    source = call.getResult(0) and
    envKey = call.getArgument(0).asExpr() and
    result = "env:" + envKey.getValue()
  )
  or
  // Function parameter
  exists(Parameter p, FuncDef f |
    source = DataFlow::parameterNode(p) and
    f = p.getFunction() and
    result = f.getName() + ":" + p.getName()
  )
  or
  // Package-level variable
  exists(Variable v |
    v.getScope() instanceof PackageScope and
    source = v.getARead() and
    result = "global:" + v.getName()
  )
  or
  // Default fallback
  not source.asExpr() instanceof StringLit and
  not exists(DataFlow::CallNode call |
    (call.getTarget().hasQualifiedName("os", "Getenv") and source = call) or
    (call.getTarget().hasQualifiedName("os", "LookupEnv") and source = call.getResult(0))
  ) and
  not exists(Parameter p | source = DataFlow::parameterNode(p)) and
  not exists(Variable v | v.getScope() instanceof PackageScope and source = v.getARead()) and
  result = "unknown:" + source.toString()
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
  sinkNode.getAwsMethodName() as serviceAction,
  sinkNode.getParameterName() as resourceName,
  sourceDetail as resourceValue,
  sourceType as valueSource
