# Es crea la clau KMS que crearà la clau, usuari root
resource "aws_kms_key" "kms_key_master" {
  description             = "Clau_kms_master"
  deletion_window_in_days = 30
  enable_key_rotation = true
  policy                  = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::272364966895:user/master"
      },
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
EOF
}
# Assegurem que tots els volums ebs estiguin xifrants per defecte
resource "aws_ebs_encryption_by_default" "esb_xifrat" {
  enabled = true
}
# es crea snapshot per ebs (còpia de següretat)
resource "aws_ebs_volume" "volume_instances" {      # es crea el volum ebs de les instances
  availability_zone = var.availability_zone
  size              = var.volume_size
  encrypted         = true
  kms_key_id        = aws_kms_key.kms_key_master.arn
}
# es crea sanpshot ciutadans
resource "aws_ebs_snapshot" "snapshot_ciutadans" {
  volume_id          = aws_ebs_volume.volume_instances.id
  description        = "Snapshot per instancia ciutadans"

  tags = {
    Name = "Snapshot Instancia_ciutadans"
  }
}
# clau per la instància, generada amb ssh-keygen -f keyCiutadans
resource "aws_key_pair" "keyCiutadans" {
  key_name   = "key_ec2Ciutadans"
  public_key = file("keyCiutadans.pub")
}
# Instància EC2 per a ciutadans
resource "aws_instance" "ec2_ciutadans" {
  ami           = var.ami_id
  instance_type = var.instance_type
  key_name      = aws_key_pair.keyCiutadans.key_name
  subnet_id     = var.subnet_ciutadans_id
  vpc_security_group_ids = [var.sg_ciutadans_id]
  monitoring    = true  # Habilitar supervisió detallada, trobat a terrascan
  tags = {
    Name = "ec2_ciutadans"
  }
  lifecycle {
    prevent_destroy = false  # per no destruir-la cada cop al fer terraform apply
  }
  # Xifra la instància
  root_block_device {
    volume_type           = "gp2"
    encrypted             = true
    kms_key_id            = aws_kms_key.kms_key_master.arn
    delete_on_termination = true
  }
  # es creen les còpies de següretat
   ebs_block_device {
    device_name           = "/dev/xvda"
    volume_type           = "gp2"
    encrypted             = true
    kms_key_id            = aws_kms_key.kms_key_master.arn
    delete_on_termination = true
    snapshot_id           = aws_ebs_snapshot.snapshot_ciutadans.id
  }
}
# Creació de la Elastic IP per la instància ciutadans
resource "aws_eip" "eip_ciutadans" {
  instance = aws_instance.ec2_ciutadans.id
}

# es crea sanpshot funcionaris
resource "aws_ebs_snapshot" "snapshot_funcionaris" {
  volume_id          = aws_ebs_volume.volume_instances.id
  description        = "Snapshot per instancia funcionaris"

  tags = {
    Name = "Snapshot Instancia_funcionaris"
  }
}

# clau per la instància, generada amb ssh-keygen -f keyCiutadans
resource "aws_key_pair" "keyFuncionaris" {
  key_name   = "key_ec2Funcionaris"
  public_key = file("keyFuncionaris.pub")
}

# Instància EC2 per a funcionaris
resource "aws_instance" "ec2_funcionaris" {
  ami           = var.ami_id
  instance_type = var.instance_type
  key_name      = aws_key_pair.keyFuncionaris.key_name
  subnet_id     = var.subnet_funcionaris_id

  vpc_security_group_ids = [var.sg_funcionaris_id]
  monitoring    = true  # Habilitar supervisió detallada, trobat a terrascan
  tags = {
    Name = "ec2_funcionaris"
  }

  lifecycle {
    prevent_destroy = false  # per no destruir-la cada cop al fer terraform apply
  }

  # Xifra la instància
  root_block_device {
    volume_type           = "gp2"
    encrypted             = true
    kms_key_id            = aws_kms_key.kms_key_master.arn
    delete_on_termination = true
  }
  # es creen les còpies de següretat
   ebs_block_device {
    device_name           = "/dev/xvda"
    volume_type           = "gp2"
    encrypted             = true
    kms_key_id            = aws_kms_key.kms_key_master.arn
    delete_on_termination = true
    snapshot_id           = aws_ebs_snapshot.snapshot_funcionaris.id
  }
}
# Creació de la Elastic IP per la instància funcionaris
resource "aws_eip" "eip_funcionaris" {
  instance = aws_instance.ec2_funcionaris.id
}


# es crea sanpshot seguretat
resource "aws_ebs_snapshot" "snapshot_seguretat" {
  volume_id          = aws_ebs_volume.volume_instances.id
  description        = "Snapshot per instancia seguretat"
  tags = {
    Name = "Snapshot Instancia_seguretat"
  }
}

# clau per la instància, generada amb ssh-keygen -f keyCiutadans
resource "aws_key_pair" "keySeguretat" {
  key_name   = "key_ec2Seguretat"
  public_key = file("keySeguretat.pub")
}

# Instància EC2 per a seguretat
resource "aws_instance" "ec2_seguretat" {
  ami           = var.ami_id
  instance_type = var.instance_type
  key_name      = aws_key_pair.keySeguretat.key_name
  subnet_id     = var.subnet_seguretat_id
  iam_instance_profile = var.cloudwatch_agent_instance_profile_name
  vpc_security_group_ids = [var.sg_seguretat_id]
  monitoring    = true  # Habilitar supervisió detallada, trobat a terrascan
  tags = {
    Name = "ec2_seguretat"
  }
  lifecycle {
    prevent_destroy = false  # per no destruir-la cada cop al fer terraform apply
  }
  # Xifra la instància
  root_block_device {
    volume_type           = "gp2"
    encrypted             = true
    kms_key_id            = aws_kms_key.kms_key_master.arn
    delete_on_termination = true
  }
  # es creen les còpies de següretat
   ebs_block_device {
    device_name           = "/dev/xvda"
    volume_type           = "gp2"
    encrypted             = true
    kms_key_id            = aws_kms_key.kms_key_master.arn
    delete_on_termination = true
    snapshot_id           = aws_ebs_snapshot.snapshot_seguretat.id
  }
}

# Creació de la Elastic IP per la instància ciutadans
resource "aws_eip" "eip_seguretat" {
  instance = aws_instance.ec2_seguretat.id
}
# Outputs per a proporcionar informació de les instàncies a altres mòduls.
output "ciutadans_instance_arn" {
  value = aws_instance.ec2_ciutadans[*].arn
}
output "funcionaris_instance_arn" {
  value = aws_instance.ec2_funcionaris[*].arn
}
output "ec2_ciutadans_id" {
  value = aws_instance.ec2_ciutadans.id
}


