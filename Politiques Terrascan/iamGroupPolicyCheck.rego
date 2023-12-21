package accurics

# Verifica que tots els grups d'usuaris tinguin polítiques assignades
{{.prefix}}{{.name}}_iam_group_policy_check[retVal] {
    group := input.aws_iam_group[_]
    policy_attachment := input.aws_iam_group_policy_attachment[_]

    group_has_policy := policy_attachment.group == group.name

    not group_has_policy

    retVal := {
        "Id": group.id, 
        "ReplaceType": "edit", 
        "CodeType": "block", 
        "Traverse": "aws_iam_group_policy_attachment",
        "Attribute": "group", 
        "AttributeDataType": "string", 
        "Expected": true, 
        "Actual": false
    }
}

