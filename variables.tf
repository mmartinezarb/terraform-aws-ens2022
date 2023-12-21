# Variable per la clau d'accés a AWS. 
variable "access_key" {
  description = "Clau d'accés a AWS"  
}
# Variable per la clau secreta d'accés a AWS. 
variable "secret_key" {
  description = "Clau secreta d'accés a AWS"
}
# Variable per definir la regió d'AWS on es crearan els recursos.
variable "region" {
  description = "Regió d'AWS on crear els recursos" # Regió
  default     = "eu-west-1"
}
# Identificador de la Imatge de Màquina d'Amazon (AMI) per a les instàncies EC2.
variable "ami_id" {
  description = "AMI ID de les instàncies"
  default     = "ami-0694d931cee176e7d"  # Canonical, Ubuntu, 22.04 LTS, amd64 jammy image build on 2023-09-19
}
# Variable per especificar el tipus d'instància EC2.
variable "instance_type" {
  description = "Tipus d'instància per a les instàncies"
  default     = "t2.micro"  # Tipus d'instància EC2 
}
# Variable per a l'ARN d'un bucket S3 usat per CloudTrail.
variable "s3_bucket_arn" {
  description = "ARN del bucket S3 de CloudTrail"
  type        = string
  default     = "arn:aws:s3:::tf-inframaster"
}
