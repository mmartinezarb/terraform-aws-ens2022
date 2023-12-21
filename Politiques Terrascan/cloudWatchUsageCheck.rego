package accurics

# Verifica l'ús de CloudWatch Log Groups
{{.prefix}}{{.name}}_cloudWatchUsageCheck[retVal] {
    log_group := input.aws_cloudwatch_log_group[_]
    
    count(log_group) > 0

    retVal := {
        "Id": log_group.id, 
        "ReplaceType": "block", 
        "CodeType": "resource", 
        "Traverse": "aws_cloudwatch_log_group",
        "Attribute": "name", 
        "AttributeDataType": "string", 
        "Expected": true, 
        "Actual": true
    }
}

