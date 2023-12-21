# Proveïdor AWS amb la regió
provider "aws" {
  region = "eu-west-1"
}
# Es crea una política per que tots els usuaris tinguin constrasenyes segures:
# una longitud mínima de la contrasenya, la necessitat de lletres minúscules, 
# majúscules, números i símbols o reutilització de contrasenyes
resource "aws_iam_account_password_policy" "password_policy" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  hard_expiry                    = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}
# Creació del grup IAM per a usuaris "ciutadans".
resource "aws_iam_group" "ciutadans" {
  name = "ciutadans"
}
# Política IAM per a controlar permisos del grup "ciutadans".
resource "aws_iam_policy" "ciutada_policy" {
  name        = "ciutada-policy"
  description = "Política per a ciutadans"
  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Action   = [
          "ec2:DescribeInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:RebootInstances",
          "ec2:TerminateInstances",
          "ec2:AuthorizeSecurityGroupIngress",
        ],
        Effect   = "Allow",
        Resource = "*"
      },
    ],
  })
}
# Creació d'un usuari IAM "usCiutada".
resource "aws_iam_user" "usCiutada" {
  name = "usCiutada"
}
# Associació de la política IAM al grup "ciutadans".
resource "aws_iam_group_policy_attachment" "ciutada_attachment" {
  policy_arn = aws_iam_policy.ciutada_policy.arn
  group      = aws_iam_group.ciutadans.name
}
# Associació de l'usuari "usCiutada" al grup "ciutadans"
resource "aws_iam_group_membership" "ciutadans_membership" {
  name = "ciutadans-membership"
  users = [aws_iam_user.usCiutada.name]
  group = aws_iam_group.ciutadans.name
}

# Es crea el grup dels funcionaris
resource "aws_iam_group" "funcionaris" {
  name = "funcionaris"
}

# Creació del grup IAM per a usuaris funcionaris
resource "aws_iam_policy" "funcionari_policy" {
  name        = "funcionari-policy"
  description = "Política per a funcionaris"
  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Action   = [
          "ec2:DescribeInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:RebootInstances",
          "ec2:TerminateInstances",
          "ec2:AuthorizeSecurityGroupIngress",
        ],
        Effect   = "Allow",
        Resource = "*"
      },
    ],
  })
}
# Es crea l'usuari usFuncionari
resource "aws_iam_user" "usFuncionari" {
  name = "usFuncionari"
}
# Associar la política amb el grup "funcionaris"
resource "aws_iam_group_policy_attachment" "funcionari_attachment" {
  policy_arn = aws_iam_policy.funcionari_policy.arn
  group      = aws_iam_group.funcionaris.name
}
# Associació de l'usuari "usFuncionari" al grup "funcionaris"
resource "aws_iam_group_membership" "funcionari_membership" {
  name = "funcionari-membership"
  users = [aws_iam_user.usFuncionari.name]
  group = aws_iam_group.funcionaris.name
}
# Es crea el grup dels seguretat
resource "aws_iam_group" "seguretat" {
  name = "seguretat"
}
# Política per a seguretat
resource "aws_iam_policy" "seguretat_policy" {
  name        = "seguretat-policy"
  description = "Política per a seguretat"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = [
          "ec2:*",
        ],
        Resource = "*",
        Effect   = "Allow",
      },
    ],
  })
}
# Política prowler
resource "aws_iam_policy" "s3_access_policy" {
  count       = var.create_s3_policy ? 1 : 0
  name        = "s3-access-policy"
  description = "Política per a l'accés al bucket S3 de CloudTrail"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = [
          "account:Get*",
          "appstream:Describe*",
          "appstream:List*",
          "backup:List*",
          "cloudtrail:GetInsightSelectors",
          "codeartifact:List*",
          "codebuild:BatchGet*",
          "dlm:Get*",
          "drs:Describe*",
          "ds:Get*",
          "ds:Describe*",
          "ds:List*",
          "ec2:GetEbsEncryptionByDefault",
          "ecr:Describe*",
          "ecr:GetRegistryScanningConfiguration",
          "elasticfilesystem:DescribeBackupPolicy",
          "glue:GetConnections",
          "glue:GetSecurityConfiguration*",
          "glue:SearchTables",
          "lambda:GetFunction*",
          "logs:FilterLogEvents",
          "macie2:GetMacieSession",
          "s3:GetAccountPublicAccessBlock",
          "shield:DescribeProtection",
          "shield:GetSubscriptionState",
          "securityhub:BatchImportFindings",
          "securityhub:GetFindings",
          "ssm:GetDocument",
          "ssm-incidents:List*",
          "support:Describe*",
          "tag:GetTagKeys",
          "wellarchitected:List*",
          "apigateway:GET",
          "s3:GetObject",
          "s3:ListBucket",
        ],
        Resource = [var.s3_bucket_arn, "${var.s3_bucket_arn}/*"],
        Effect   = "Allow",
      },
    ],
  })
}
# Política accés a totes les ec2
resource "aws_iam_policy" "seguretat_additional_policy" {
  name        = "seguretat-ec2-policy"
  description = "Política addicional per a seguretat"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = ["ec2:*"],
        Resource = "*",
        Effect   = "Allow",
      },
    ],
  })
}
# Es crea l'usuari usSeguretat
resource "aws_iam_user" "usSeguretat" {
  name = "usSeguretat"
}
# Associar la política "seguretat_policy" al grup "seguretat"
resource "aws_iam_group_policy_attachment" "seguretat_policy_attachment" {
  policy_arn = aws_iam_policy.seguretat_policy.arn
  group      = aws_iam_group.seguretat.name
}
# Associació de l'usuari "usSeguretat" al grup "seguretat"
resource "aws_iam_group_membership" "seguretat_membership" {
  name = "seguretat-membership"
  users = [aws_iam_user.usSeguretat.name]
  group = aws_iam_group.seguretat.name
}
# Assignar la política "s3_access_policy" al grup "seguretat"
resource "aws_iam_group_policy_attachment" "s3_access_policy_attachment" {
  count = var.create_s3_policy ? 1 : 0
  policy_arn = aws_iam_policy.s3_access_policy[0].arn
  group = aws_iam_group.seguretat.name
}
# Assignar la política "seguretat_additional_policy" al grup "seguretat"
resource "aws_iam_group_policy_attachment" "seguretat_additional_policy_attachment" {
  policy_arn = aws_iam_policy.seguretat_additional_policy.arn
  group      = aws_iam_group.seguretat.name
}
# Politica per enviar la informació de prowler a security hub
resource "aws_iam_policy" "security_hub_policy" {
  name        = "security-hub-policy"
  description = "Política per a l'accés a AWS Security Hub"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "securityhub:BatchImportFindings",
          "securityhub:GetFindings"
        ],
        Resource = "*",
        Effect   = "Allow",
      },
    ],
  })
}
# Associar la nova política al grup "seguretat"
resource "aws_iam_group_policy_attachment" "security_hub_policy_attachment" {
  policy_arn = aws_iam_policy.security_hub_policy.arn
  group      = aws_iam_group.seguretat.name
}
# Creació del iam per la instancia de seguretat per cloudwatch
resource "aws_iam_role" "cloudwatch_agent_role" {
  name = "cloudwatch_agent_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
      },
    ],
  })
}
# Associació de la política CloudWatch Agent al rol creat.
resource "aws_iam_role_policy_attachment" "cloudwatch_agent_policy_attachment" {
  role       = aws_iam_role.cloudwatch_agent_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}
# Creació d'un perfil d'instància IAM per al rol de CloudWatch Agent.
resource "aws_iam_instance_profile" "cloudwatch_agent_instance_profile" {
  name = "cloudwatch_agent_instance_profile"
  role = aws_iam_role.cloudwatch_agent_role.name
}

# Permisos per script de copies de snapshots
resource "aws_iam_policy" "copia_snapshot" {
  name        = "copia_snapshot"
  description = "Política amb permisos addicionals per la creació de captures instantànies"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:CreateTags",
          "ec2:CreateSnapshot",
          "ec2:DeleteSnapshot",
          "ec2:DescribeSnapshots",
          "ssm:UpdateInstanceInformation",
          "logs:PutRetentionPolicy"
        ],
        Resource = "*"
      }
    ]
  })
}
# Associació de la política de captures instantànies al rol CloudWatch Agent.
resource "aws_iam_role_policy_attachment" "copia_snapshot_attachment" {
  role       = aws_iam_role.cloudwatch_agent_role.name
  policy_arn = aws_iam_policy.copia_snapshot.arn
}
# Outputs per compartir informació amb altres mòduls Terraform.
output "cloudwatch_agent_instance_profile_name" {
  value = aws_iam_instance_profile.cloudwatch_agent_instance_profile.name
}
output "cloudwatch_agent_role_arn" {
  value = aws_iam_role.cloudwatch_agent_role.arn
}
output "cloudwatch_agent_role_name" {
  value = aws_iam_role.cloudwatch_agent_role.name
}
