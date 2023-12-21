# Variable per a l'identificador de la Imatge de Màquina Amazon (AMI) 
variable "ami_id" {
  description = "ID de l'AMI per a les instàncies EC2"
}
# Variable per definir el tipus d'instància EC2.
variable "instance_type" {
  description = "Tipus d'instància EC2"
}

variable "sg_ciutadans_id" {
  description = "ID del security group de la instància de ciutadans"

}

variable "sg_funcionaris_id" {
  description = "ID del security group de la instància de funcionaris"
  
}

variable "sg_seguretat_id" {
  description = "ID del security group de la instància de seguretat"
  
}

variable "subnet_ciutadans_id" {
  description = "ID de la subxarxa per a les instàncies de ciutadans"
}

variable "subnet_funcionaris_id" {
  description = "ID de la subxarxa per a les instàncies de funcionaris"
}

variable "subnet_seguretat_id" {
  description = "ID de la subxarxa per a les instàncies de seguretat"
}
# Variable per al nom de perfil d'instància IAM per a CloudWatch.
variable "cloudwatch_agent_instance_profile_name" {
  type    = string
  default = ""
}

variable "availability_zone" {
  description = "The availability zone for the EBS volume"
  default     = "eu-west-1a" # zona on es crearà el volum ebs
}

variable "volume_size" {
  description = "La mida del volum EBS en GB"
  default     = 50  # tamany del volum en GB
}
