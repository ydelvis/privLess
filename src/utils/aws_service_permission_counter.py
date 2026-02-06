import json
from typing import Dict

def count_permissions_per_service(aws_services_json: str) -> Dict[str, int]:
    with open(aws_services_json, 'r') as f:
        aws_services = json.load(f)

    permission_count = {}
    for service in aws_services:
        count = len(aws_services[service])
        permission_count[service.lower()] = count

    return permission_count

if __name__ == "__main__":
    aws_services_json = 'data/iam_service_actions.json'
    permission_count = count_permissions_per_service(aws_services_json)
    
    json_output_path = 'data/permission_count.json'
    with open(json_output_path, 'w') as f:
        json.dump(permission_count, f, indent=4)