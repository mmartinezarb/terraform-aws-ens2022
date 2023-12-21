package accurics

# Verifica l'ús de CloudTrail
{{.prefix}}{{.name}}_cloudTrailUsageCheck[retVal] {
    cloudtrail := input.aws_cloudtrail[_]
    
    count(cloudtrail) > 0

    retVal := {
        "Id": cloudtrail.id, 
        "ReplaceType": "block", 
        "CodeType": "resource", 
        "Traverse": "aws_cloudtrail",
        "Attribute": "name", 
        "AttributeDataType": "string", 
        "Expected": true, 
        "Actual": true
    }
}

