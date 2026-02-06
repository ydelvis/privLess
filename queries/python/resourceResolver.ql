
/**
 * @name AWS Resource Parameter Value Tracking
 * @description Tracks data flow from various sources to AWS service resource parameters
 * @kind table
 * @id python/aws-resource-value-tracking
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

/**
 * AWS resource parameter names across key services
 */
predicate isAwsResourceParameter(string paramName) {
  paramName in [
    "Bucket", "Key",  // S3 Bucket and Object Key
    "FunctionName",  // Lambda Function Name
    "QueueName", "QueueUrl", // SQS Queue Name
    "TopicName", "TopicArn", "TargetArn", "SubscriptionArn", //  SNS Topic Name
    "TableName", // DynamoDB Table Name
    "StateMachineName",  "StateMachineArn",  // Step Functions State Machine Name
    "DomainName",  // AppSync, Route53 Domain Name
    "StreamName", "StreamArn", // Kinesis Stream Name
    "ClusterName", "Cluster", "ClusterResourceId",  // ECS Cluster Name
    "DBInstanceIdentifier", "DBClusterIdentifier", // RDS Instance Identifier
    "AccessPointId",  // EFS Access Point Name,
    "LogGroupName", "MetricName", "Namespace", // CloudWatch Log Group Name
    "AppId", "ApplicationId",  // Pinpoint Application ID
    "ThingName", "ThingGroupName", "StreamId",  // IoT Thing and Thing Group Names
    "ApiId" // AppSync
  ]
}

/**
 * Gets a boto3 client or resource API call
 */
API::Node getBoto3Api() {
  result = API::moduleImport("boto3").getMember(["client", "resource"]).getReturn()
}

/**
 * A sink that represents an AWS resource parameter
 */
class AwsResourceParameterSink extends DataFlow::Node {
  string parameterName;
  
  AwsResourceParameterSink() {
    exists(DataFlow::CallCfgNode call, DataFlow::Node arg |
      // Call to a boto3 client/resource method
      call = getBoto3Api().getMember(_).getACall() and
      // Get keyword argument
      arg = call.getArgByName(parameterName) and
      isAwsResourceParameter(parameterName) and
      this = arg
    )
  }
  
  string getParameterName() { result = parameterName }
  
  string getAwsMethodName() {
    exists(DataFlow::CallCfgNode call |
      this = call.getArgByName(parameterName) and
      call = getBoto3Api().getMember(result).getACall()
    )
  }
}

/**
 * Configuration for tracking values to AWS resource parameters
 */
module AwsResourceValueConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // String literals
    source.asExpr() instanceof StringLiteral
    or
    // Environment variables - os.environ['KEY']
    exists(SubscriptNode sub |
      sub = source.asCfgNode() and
      sub.getObject().(AttrNode).getName() = "environ"
    )
    or
    // Environment variables - os.getenv('KEY')
    source = API::moduleImport("os").getMember("getenv").getACall()
    or
    // Environment variables - os.environ.get('KEY')
    exists(AttrNode attr |
      attr = source.asCfgNode().(CallNode).getFunction() and
      attr.getName() = "get" and
      attr.getObject().(AttrNode).getName() = "environ"
    )
    or
    // Function parameters
    exists(Parameter p | source.asExpr() = p.asName())
    or
    // Global/module-level variable assignments
    exists(AssignStmt assign |
      assign.getScope() instanceof Module and
      source.asExpr() = assign.getValue()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof AwsResourceParameterSink
  }
}

module AwsResourceFlow = TaintTracking::Global<AwsResourceValueConfig>;

/**
 * Classify the source type and extract details
 */
string getSourceType(DataFlow::Node source) {
  source.asExpr() instanceof StringLiteral and result = "LITERAL"
  or
  exists(SubscriptNode sub |
    sub = source.asCfgNode() and
    sub.getObject().(AttrNode).getName() = "environ" and
    result = "ENV_VAR"
  )
  or
  source = API::moduleImport("os").getMember("getenv").getACall() and 
  result = "ENV_VAR"
  or
  exists(AttrNode attr |
    attr = source.asCfgNode().(CallNode).getFunction() and
    attr.getName() = "get" and
    attr.getObject().(AttrNode).getName() = "environ" and
    result = "ENV_VAR"
  )
  or
  exists(Parameter p | source.asExpr() = p.asName() and result = "PARAMETER")
  or
  exists(AssignStmt assign |
    assign.getScope() instanceof Module and
    source.asExpr() = assign.getValue() and
    result = "GLOBAL_VAR"
  )
}

string getSourceDetail(DataFlow::Node source) {
  // String literal value
  result = source.asExpr().(StringLiteral).getS()
  or
  // Environment variable name
  exists(SubscriptNode sub, StringLiteral key |
    sub = source.asCfgNode() and
    sub.getObject().(AttrNode).getName() = "environ" and
    key = sub.getIndex().getNode() and
    result = "env:" + key.getS()
  )
  or
  // os.getenv('KEY')
  exists(DataFlow::CallCfgNode call, StringLiteral key |
    call = API::moduleImport("os").getMember("getenv").getACall() and
    source = call and
    key = call.getArg(0).asExpr() and
    result = "env:" + key.getS()
  )
  or
  // Parameter name
  exists(Parameter p, Function f |
    source.asExpr() = p.asName() and
    p = f.getAnArg() and
    result = f.getName() + ":" + p.asName().getId()
  )
  or
  // Global variable name
  exists(AssignStmt assign, Name target |
    assign.getScope() instanceof Module and
    source.asExpr() = assign.getValue() and
    target = assign.getATarget() and
    result = "global:" + target.getId()
  )
  or
  // Default
  not exists(StringLiteral s | s = source.asExpr()) and
  not exists(SubscriptNode sub | sub = source.asCfgNode() and sub.getObject().(AttrNode).getName() = "environ") and
  not source = API::moduleImport("os").getMember("getenv").getACall() and
  not exists(Parameter p | p.asName() = source.asExpr()) and
  not exists(AssignStmt assign | assign.getScope() instanceof Module and assign.getValue() = source.asExpr()) and
  result = "global:" + source.toString()
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
  sink.getNode().getLocation()          as path,
  sinkNode.getAwsMethodName()           as serviceAction,
  sinkNode.getParameterName()           as resourceName,
  sourceDetail                          as resourceValue,
  sourceType                            as valueSource