# Variable creació grups ciutadans
variable "create_ciutadans_group" {
  description = "Crea el grup IAM per a ciutadans"
  type        = bool
  default     = false
}
# Variable creació grups funcionaris
variable "create_funcionaris_group" {
  description = "Crea el grup IAM per a funcionaris"
  type        = bool
  default     = false
}
# Variable creació grups seguretat
variable "create_seguretat_group" {
  description = "Crea el grup IAM per a seguretat"
  type        = bool
  default     = false
}
# Variable per crear la política IAM per a l'accés al bucket S3 de CloudTrail.
variable "create_s3_policy" {
  description = "Crea una política IAM per a l'accés al bucket S3 de CloudTrail"
  type        = bool
  default     = false
}
# Variable per emmagatzemar l'ARN del bucket S3 utilitzat per CloudTrail.
variable "s3_bucket_arn" {
  description = "ARN del bucket S3 de CloudTrail"
  type        = string
  default     = "ARN_DEL_BUCKET_S3"
}
# Variable per emmagatzemar l'ARN de la instància EC2 "ciutadans".
variable "ciutadans_instance_arn" {
  description = "ARN de la instància EC2 per a ciutadans"
}
# Variable per emmagatzemar l'ARN de la instància EC2 "funcionaris".
variable "funcionaris_instance_arn" {
  description = "ARN de la instància EC2 per als funcionaris"
}
