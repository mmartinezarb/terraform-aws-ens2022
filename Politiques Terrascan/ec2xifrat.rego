package accurics

# Verifica l'encriptació dels volums EBS
{{.prefix}}{{.name}}_ebs_encrypted[retVal] {
    ebs := input.aws_ebs_volume[_]
    isEncrypted := checkEncryption(ebs.encrypted)
    traverse := "encrypted"
    retVal := {
        "Id": ebs.id, "ReplaceType": "edit", "CodeType": "attribute", "Traverse": traverse,
        "Attribute": "encrypted", "AttributeDataType": "bool", "Expected": true,
        "Actual": isEncrypted
    }
}

# Verifica l'encriptació de les instàncies EC2
{{.prefix}}{{.name}}_ec2_encrypted[retVal] {
    instance := input.aws_instance[_]
    isEncrypted := checkEncryption(instance.root_block_device.encrypted)
    traverse := "root_block_device.encrypted"
    retVal := {
        "Id": instance.id, "ReplaceType": "edit", "CodeType": "attribute", "Traverse": traverse,
        "Attribute": "encrypted", "AttributeDataType": "bool", "Expected": true,
        "Actual": isEncrypted
    }
}

# Funció auxiliar per verificar l'encriptació
checkEncryption(encrypted) = encrypted {
    encrypted
} else = false {
    not encrypted
}

