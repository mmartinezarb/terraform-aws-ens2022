# Variable per al CIDR block de la VPC de Ciutadans
variable "vpc_cidr_block_ciutadans" {
  description = "CIDR block per a la VPC de Ciutadans"
  type        = string
}

# Variable per al CIDR block de la VPC de Funcionaris
variable "vpc_cidr_block_funcionaris" {
  description = "CIDR block per a la VPC de Funcionaris"
  type        = string
}

# Variable per al CIDR block de la VPC de Seguretat i Gestió
variable "vpc_cidr_block_seguretat" {
  description = "CIDR block per a la VPC de Seguretat i Gestió"
  type        = string
}


variable "availability_zone" {
  description = "The availability zone "
  default     = "eu-west-1a" # zona on es crearà 
}

# variables per les subnets
variable "create_subnet_ciutadans" {
  description = "Crea la Subnet ciutadans"
  type        = bool
  default     = true
}

variable "subnet_ciutadans_cidr_block" {
  description = "CIDR block de la Subnet ciutadans"
  default     = "10.0.1.0/24"
}

variable "subnet_a_availability_zone" {
  description = "Zona de disponibilitat per a la Subnet ciutadans"
  default     = "eu-west-1a"
}

variable "create_subnet_funcionaris" {
  description = "Crea la Subnet funcionaris"
  type        = bool
  default     = true
}

variable "subnet_funcionaris_cidr_block" {
  description = "CIDR block de la Subnet funcionaris"
  default     = "10.0.2.0/24"
}

variable "subnet_funcionaris_availability_zone" {
  description = "Zona de disponibilitat per a la Subnet funcionaris"
  default     = "eu-west-1a"
}

variable "subnet_ciutadans_availability_zone" {
  description = "Zona de disponibilitat per a la Subnet ciutadans"
  default     = "eu-west-1a"
}

variable "create_subnet_seguretat" {
  description = "Crea la Subnet seguretat"
  type        = bool
  default     = true  
}

variable "subnet_seguretat_cidr_block" {
  description = "CIDR block de la Subnet seguretat"
  default     = "10.0.3.0/24"  
}

variable "subnet_seguretat_availability_zone" {
  description = "Zona de disponibilitat per a la Subnet seguretat"
  default     = "eu-west-1a"  
}

# Dins del mòdul de xarxa
variable "ec2_ciutadans_id" {
  description = "ID de la instància EC2 de ciutadans que opera com a servidor VPN"
  type        = string
}
