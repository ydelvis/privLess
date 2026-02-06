/**
 * @name Detect Boto3 Calls with Arguments
 * @description Identifies all boto3 service calls
 * @kind table
 * @id python/detect-boto3-calls-with-args
 */

import python
import semmle.python.ApiGraphs


predicate matchesServiceFilter(string serviceName) {
  // Filter by service name
  serviceName in  [
    "s3", "dynamodb", "sns", "lambda"] // Todo: Add all supported services
}

//Todo: try to resolve direct values here
// predicate getResourceValue(Node arg){
//   arg.asExpr().(StringLiteral).isConstant() and 

// }

from 
  API::CallNode serviceCall,
  string service,
  API::CallNode serviceActionCall,
  string serviceAction,
  string variableName,
  string resourceName,
  string resourceValue
where
  // Match boto3.client('service_name') or boto3.resource('service_name')
  (
    serviceCall = API::moduleImport("boto3").getMember("client").getACall() or
    serviceCall = API::moduleImport("boto3").getMember("resource").getACall()
  ) and
  
  // Get the service name from the first argument
  service = serviceCall.getArg(0).asExpr().(StrConst).getText() and
  
  // Track the client to a variable assignment
  exists(AssignStmt assign |
    assign.getValue() = serviceCall.asExpr() and
    assign.getATarget().(Name).getId() = variableName
  ) and
  
  // Apply filters (comment out BOTH lines below to see all results)
  //matchesServiceFilter(service) and
  
  // Find method calls on the returned client/resource object
   serviceActionCall = serviceCall.getReturn().getMember(serviceAction).getACall() and
  // exists(serviceActionCall.getArgByName(resourceName)) 

  resourceValue = serviceActionCall.getArgByName(resourceName).asExpr().toString()
  
select 
  serviceActionCall.getLocation() as path, //.getFile().getAbsolutePath() as path,
  //variableName,
  service,
  serviceAction,
  resourceName,
  resourceValue
