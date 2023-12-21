variable "vpc_id" {
  description = "L'identificador de la VPC a la qual connectar els serveis."
  type        = string
}

variable "cloudwatch_agent_role_arn" {
  description = "ARN del rol IAM per l'agent de CloudWatch"
  type        = string
}

variable "cloudwatch_agent_role_name" {
  description = "Nom del rol IAM per l'agent de CloudWatch"
  type        = string
}

