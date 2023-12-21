provider "aws" {
  region = "eu-west-1" # Especifica la regió on es desplegaran els recursos
}

# Recopila informació sobre l'entitat actual d'AWS, la partició actual i la regió actual
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
# Crea una clau KMS per al xifrat dels logs de CloudTrail
resource "aws_kms_key" "cloudtrail_kms_key" {
  description             = "KMS key for CloudTrail logs"
  enable_key_rotation     = true
  deletion_window_in_days = 10

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "key-default-1",
  "Statement": [
    {
      "Sid": "Allow CloudTrail to use KMS key",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "kms:GenerateDataKey*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
        }
      }
    },
    {
      "Sid": "Allow CloudWatch Logs to use KMS key", 
      "Effect": "Allow",
      "Principal": {
        "Service": "logs.eu-west-1.amazonaws.com"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Allow CloudTrail to describe key",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "kms:DescribeKey",
      "Resource": "*"
    },
    {
      "Sid": "Allow access for Key Administrators",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::272364966895:user/master"
      },
      "Action": [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion"
      ],
      "Resource": "*"
    }
  ]
}
POLICY
}

# Primer es crearà el log de CloudWatch, si no dona errors amb arn
# Seguidament es torna a aplicar terraform apply amb tot el codi

# Crea un grup de logs a CloudWatch per CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrailinframaster_log_group" {
  name              = "CloudTrail/inframaster-log-group"
  retention_in_days = 365
  #Es xifra el log utilitza la clau generada per xifrar cloudTrail
  kms_key_id        = aws_kms_key.cloudtrail_kms_key.arn  
}

# Crea un bucket S3 per a logs de CloudTrail amb xifrat i versionament
resource "aws_s3_bucket" "bucketinframaster" {
  bucket        = "tf-inframaster-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.cloudtrail_kms_key.arn
      }
    }
  }
}

# Política IAM per al bucket S3 que permet a CloudTrail escriure logs
data "aws_iam_policy_document" "policydocumentinframaster" {
  # Permet a CloudTrail comprovar l'ACL del bucket
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.bucketinframaster.arn]
  }

  # Permet a CloudTrail escriure logs al bucket
  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.bucketinframaster.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

# Aplica la política al bucket S3
resource "aws_s3_bucket_policy" "bucketpolicyinframaster" {
  bucket = aws_s3_bucket.bucketinframaster.id
  policy = data.aws_iam_policy_document.policydocumentinframaster.json
}

# Crea una IAM role per a CloudWatch Logs que permet a CloudTrail publicar logs
resource "aws_iam_role" "cloudtrail_cloudwatch_logs_role" {
  name               = "cloudtrail_cloudwatch_logs_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      },
    }],
  })
}

# Política IAM que permet a CloudTrail publicar logs a CloudWatch Logs
resource "aws_iam_policy" "cloudtrail_cloudwatch_logs_policy" {
  name        = "cloudtrail_cloudwatch_logs_policy"
  description = "Permet a CloudTrail publicar logs a CloudWatch Logs"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"],
      Effect   = "Allow",
      Resource = "arn:aws:logs:eu-west-1:272364966895:log-group:CloudTrail/inframaster-log-group:*"  # afegir comentaris problemes amb cloudwatch
    }],
  })
}

# Adjunta la política IAM a la role de CloudWatch Logs
resource "aws_iam_role_policy_attachment" "cloudtrail_cloudwatch_logs_policy_attachment" {
  role       = aws_iam_role.cloudtrail_cloudwatch_logs_role.name
  policy_arn = aws_iam_policy.cloudtrail_cloudwatch_logs_policy.arn
}

# Configura CloudTrail per registrar events
resource "aws_cloudtrail" "cloudtrailinframaster" {
  name                          = "cloudtrailinframaster"
  s3_bucket_name                = aws_s3_bucket.bucketinframaster.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail_kms_key.arn
  # Afegir Data Events a CloudTrail
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::${aws_s3_bucket.bucketinframaster.bucket}/*"]
    }
  }

  # Especifica l'ARN del grup de logs de CloudWatch
  # s'ha creat previament amb terraform apply i havia creat un error, es recupera de aws directament
  cloud_watch_logs_group_arn = "arn:aws:logs:eu-west-1:272364966895:log-group:CloudTrail/inframaster-log-group:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch_logs_role.arn

  # Assegurar que el grup de logs es crea primer
  depends_on = [aws_cloudwatch_log_group.cloudtrailinframaster_log_group]
}

# Es creen alarmes de cloudWatch
# Creació d'un tema SNS per a notificacions
resource "aws_sns_topic" "cloudtrail_alerts_topic" {
  name = "cloudtrail-alerts-topic"
}

# Subscripció a SNS per rebre notificacions per correu electrònic
resource "aws_sns_topic_subscription" "cloudtrail_alerts_email_subscription" {
  topic_arn = aws_sns_topic.cloudtrail_alerts_topic.arn
  protocol  = "email"
  endpoint  = "mmartinezarb@uoc.edu"  # Adreça de correu electrònic
}

# Activació de security hub per rebre prowler
# Caldrà acceptar els informes de prowler a security hub a la consola de aws
resource "aws_securityhub_account" "prowler_security_hub_account" {}


# Filtre de mètriques per detectar canvis de configuració en CloudTrail
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_config_changes_metric_filter" {
  name           = "CloudTrailConfigChanges"
  pattern        = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
  log_group_name = aws_cloudwatch_log_group.cloudtrailinframaster_log_group.name

  metric_transformation {
    name      = "CloudTrailConfigChangesCount"
    namespace = "Custom/CloudTrailMetrics"
    value     = "1"

  }
}

# Alarma de CloudWatch quan es detecten canvis de configuració en CloudTrail
resource "aws_cloudwatch_metric_alarm" "cloudtrail_config_changes_alarm" {
  alarm_name          = "CloudTrailConfigChangesAlarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CloudTrailConfigChangesCount"
  namespace           = "Custom/CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Alarma: Canvis en la configuració de CloudTrail."
  alarm_actions       = [aws_sns_topic.cloudtrail_alerts_topic.arn]
}

# Filtre de mètriques de CloudWatch per detectar canvis en les polítiques IAM
resource "aws_cloudwatch_log_metric_filter" "iam_policy_change_metric_filter" {
  name           = "IAMPolicyChangeMetricFilter"
  pattern        = "{ ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) }"
  log_group_name = aws_cloudwatch_log_group.cloudtrailinframaster_log_group.name

  metric_transformation {
    name      = "IAMPolicyChangeCount"
    namespace = "Custom/CloudTrailMetrics"
    value     = "1"
  }
}

# Alarma de CloudWatch per canvis en les polítiques IAM
resource "aws_cloudwatch_metric_alarm" "iam_policy_change_alarm" {
  alarm_name          = "IAMPolicyChangeAlarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "IAMPolicyChangeCount"
  namespace           = "Custom/CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Alarma: Canvis en les polítiques IAM detectats."
  alarm_actions       = [aws_sns_topic.cloudtrail_alerts_topic.arn]
}

# IAM Role per a Flow Logs política de terrascan
resource "aws_iam_role" "flow_log_role" {
  name = "vpc_flow_log_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })
}
# IAM per a la role
resource "aws_iam_policy" "flow_log_policy" {
  name        = "vpc_flow_log_policy"
  description = "Permet a VPC Flow Logs escriure a CloudWatch Logs"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"],
      Effect   = "Allow",
      Resource = "arn:aws:logs:*:*:*"
    }]
  })
}
# Adjuntar la política al rol
resource "aws_iam_role_policy_attachment" "flow_log_policy_attachment" {
  role       = aws_iam_role.flow_log_role.name
  policy_arn = aws_iam_policy.flow_log_policy.arn
}
# CloudWatch Log Group per als registres de flux
resource "aws_cloudwatch_log_group" "vpc_flow_log_group" {
  name = "VPCFlowLogs/vpc-flow-log-group"
}
# recurs de Flow Log
resource "aws_flow_log" "vpc_flow_log" {
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_log_group.arn
  traffic_type    = "ALL"
  vpc_id = var.vpc_id  # ID de la VPC de seguretat i gestió
  depends_on      = [aws_cloudwatch_log_group.vpc_flow_log_group]
}

# Cloudwatch per Prowler
# Política per que l'agent cloudtrail pugui xifrar i desxifrar el log
resource "aws_iam_policy" "ec2_kms_policy" {
  name        = "ec2_kms_policy"
  description = "Permet a l'agent de CloudWatch a l'EC2 utilitzar la clau KMS"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = [aws_kms_key.cloudtrail_kms_key.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_kms_policy_attachment" {
  role       = var.cloudwatch_agent_role_name
  policy_arn = aws_iam_policy.ec2_kms_policy.arn
}

# Recurs de cloudwatch pels logs de prowler
resource "aws_cloudwatch_log_group" "prowler_log_group" {
  name              = "prowler_log_group"
  #retention_in_days = 365  
  #Es xifra el log utilitza la clau generada per xifrar cloudTrail
  kms_key_id        = aws_kms_key.cloudtrail_kms_key.arn 
}
# Consulta amb totes les troballes que son requisits i no han pasat alguna política
resource "aws_cloudwatch_query_definition" "fail_requisito" {
  name           = "fail_requisito_query"
  query_string   = "fields @timestamp, @message, REQUIREMENTS_ID, REQUIREMENTS_ATTRIBUTES_NIVEL, REQUIREMENTS_ATTRIBUTES_TIPO, STATUS | filter STATUS like /FAIL/ and REQUIREMENTS_ATTRIBUTES_TIPO = \"requisito\""
  log_group_names = [aws_cloudwatch_log_group.prowler_log_group.name]
}
# Consulta amb les troballes que son requisit que afectin a instàncies EC2
resource "aws_cloudwatch_query_definition" "ec2_fail_requisito" {
  name           = "ec2_fail_requisito_query"
  query_string   = "fields @timestamp, @message, STATUS, REQUIREMENTS_ATTRIBUTES_TIPO, CHECKID | filter STATUS = \"FAIL\" and REQUIREMENTS_ATTRIBUTES_TIPO = \"requisito\" and CHECKID like /ec2/"
  log_group_names = [aws_cloudwatch_log_group.prowler_log_group.name]
}

# Creació d'un panell de dashboard a AWS CloudWatch
resource "aws_cloudwatch_dashboard" "Panell_ens_2022" {
  # Nom del panell
  dashboard_name = "ENS_2022"
  # Definició del cos del panell utilitzant una estructura JSON
  dashboard_body = jsonencode({
    widgets: [
      # Widget de tipus log: Mostra dades en format de gràfic
      {
        type: "log",
        x: 0,
        y: 0,
        width: 8,
        height: 6,
        properties: {
          query: "SOURCE '${aws_cloudwatch_log_group.prowler_log_group.name}' | fields @timestamp, @message, STATUS | stats count() as Troballes by STATUS",
          view: "pie",
          title: "Troballes ENS-2022"
        }
      },
      # Widget de log: Mostra dades de fallades específiques en format de gràfic 
      {
        type: "log",
        x: 0,
        y: 6,
        width: 8,
        height: 6,
        properties: {
          query: "SOURCE '${aws_cloudwatch_log_group.prowler_log_group.name}' | fields @timestamp, @message, STATUS, REQUIREMENTS_ATTRIBUTES_TIPO, CHECKID | filter STATUS = 'FAIL' and REQUIREMENTS_ATTRIBUTES_TIPO = 'requisito' and (CHECKID like /ec2/ or CHECKID like /vpc/ or CHECKID like /iam/) | stats count() as Troballes by CHECKID",
          view: "pie",
          title: "Troballes FAIL, requisit, EC2/VPC/IAM"
        }
      },
      # Widget de tipus log: Mostra dades en format de taula per a fallades generals
      {
        type: "log",
        x: 4,
        y: 0,
        width: 8,
        height: 6,
        properties: {
          query: "SOURCE '${aws_cloudwatch_log_group.prowler_log_group.name}' | fields @timestamp, @message, REQUIREMENTS_ATTRIBUTES_TIPO, STATUS | filter STATUS = 'FAIL' and REQUIREMENTS_ATTRIBUTES_TIPO = 'requisito'",
          view: "table",
          title: "Troballes FAIL, requisits ENS-2022"
        }
      },    
      # Widget de log per a fallades EC2 específiques en format de taula
      {
        type: "log",
        x: 4,
        y: 12,
        width: 8,
        height: 6,
        properties: {
          query: "SOURCE '${aws_cloudwatch_log_group.prowler_log_group.name}' | fields @timestamp, @message, STATUS, REQUIREMENTS_ATTRIBUTES_TIPO, CHECKID | filter STATUS = 'FAIL' and REQUIREMENTS_ATTRIBUTES_TIPO = 'requisito' and CHECKID like /ec2/",
          view: "table",
          title: "Troballes EC2, requisits ENS-2022"
        }
      },
      # Widget de log per a fallades VPC específiques
      {
        type: "log",
        x: 8,
        y: 0,
        width: 8,
        height: 6,
        properties: {
          query: "SOURCE '${aws_cloudwatch_log_group.prowler_log_group.name}' | fields @timestamp, @message, STATUS, REQUIREMENTS_ATTRIBUTES_TIPO, CHECKID | filter STATUS = 'FAIL' and REQUIREMENTS_ATTRIBUTES_TIPO = 'requisito' and CHECKID like /vpc/",
          view: "table",
          title: "Troballes VPC, requisits ENS-2022"
        }
      },

      # Widget de log per a fallades generals amb un gràfic de barres
      {
        type: "log",
        x: 0,
        y: 6,
        width: 8,
        height: 6,
        properties: {
          query: "SOURCE '${aws_cloudwatch_log_group.prowler_log_group.name}' | fields @timestamp, @message, STATUS, REQUIREMENTS_ATTRIBUTES_TIPO, CHECKID, RESOURCE_TYPE, DATE | filter STATUS = 'FAIL' and REQUIREMENTS_ATTRIBUTES_TIPO = 'requisito' | stats count(*) as Troballes by CHECKID, RESOURCE_TYPE, DATE | sort by Troballes desc",
          view: "bar",
          title: "Troballes FAIL, requisits ENS-2022 (Gràfic de barres)"
       }
      },

      # Widget de log per a fallades IAM específiques
      {
        type: "log",
        x: 8,
        y: 12,
        width: 8,
        height: 6,
        properties: {
          query: "SOURCE '${aws_cloudwatch_log_group.prowler_log_group.name}' | fields @timestamp, @message, STATUS, REQUIREMENTS_ATTRIBUTES_TIPO, CHECKID | filter STATUS = 'FAIL' and REQUIREMENTS_ATTRIBUTES_TIPO = 'requisito' and CHECKID like /IAM/",
          view: "table",
          title: "Troballes IAM, requisits ENS-2022"
        }
      },
      # Widget de tipus log compara els últims grups de troballes 
      {
        type: "log",
        x: 0,    
        y: 18,     
        width: 24, 
        height: 6, 
        properties: {
          query: "SOURCE '${aws_cloudwatch_log_group.prowler_log_group.name}' | fields @timestamp, @message | parse @message '{\"PROVIDER\":*}' as jsonMessage | stats count() by bin(1h) as hourlyBin | sort hourlyBin desc | limit 2",
          view: "bar",
         title: "Comparació troballes dos últims registres"
        }
      } 
    ]
  })
}

