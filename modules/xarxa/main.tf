# Creació de VPCs separades
resource "aws_vpc" "vpc_ciutadans" {
  cidr_block           = var.vpc_cidr_block_ciutadans
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "VPC Ciutadans"
  }
}

resource "aws_vpc" "vpc_funcionaris" {
  cidr_block           = var.vpc_cidr_block_funcionaris
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "VPC Funcionaris"
  }
}

resource "aws_vpc" "vpc_seguretat" {
  cidr_block           = var.vpc_cidr_block_seguretat
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "VPC Seguretat"
  }
}

# Creació d'Internet Gateway per a cada VPC
resource "aws_internet_gateway" "igw_ciutadans" {
  vpc_id = aws_vpc.vpc_ciutadans.id
  tags = {
    Name = "IGW Ciutadans"
  }
}

resource "aws_internet_gateway" "igw_funcionaris" {
  vpc_id = aws_vpc.vpc_funcionaris.id
  tags = {
    Name = "IGW Funcionaris"
  }
}

resource "aws_internet_gateway" "igw_seguretat" {
  vpc_id = aws_vpc.vpc_seguretat.id
  tags = {
    Name = "IGW Seguretat"
  }
}

# Creació de subxarxes
resource "aws_subnet" "subnet_ciutadans" {
  count                   = var.create_subnet_ciutadans ? 1 : 0
  vpc_id                  = aws_vpc.vpc_ciutadans.id
  cidr_block              = var.subnet_ciutadans_cidr_block
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name = "Subxarxa Ciutadans"
  }
}

resource "aws_subnet" "subnet_funcionaris" {
  count                   = var.create_subnet_funcionaris ? 1 : 0
  vpc_id                  = aws_vpc.vpc_funcionaris.id
  cidr_block              = var.subnet_funcionaris_cidr_block
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name = "Subxarxa Funcionaris"
  }
}

resource "aws_subnet" "subnet_seguretat" {
  count                   = var.create_subnet_seguretat ? 1 : 0
  vpc_id                  = aws_vpc.vpc_seguretat.id
  cidr_block              = var.subnet_seguretat_cidr_block
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name = "Subxarxa Seguretat"
  }
}

# Creació de taules d'enrutament per a cada VPC
# primer s'ha de tenir la vpc_peering_connection creada
resource "aws_route_table" "rt_ciutadans" {
  vpc_id = aws_vpc.vpc_ciutadans.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw_ciutadans.id
  }
  tags = {
    Name = "RT Ciutadans"
  }
}

resource "aws_route_table" "rt_funcionaris" {
  vpc_id = aws_vpc.vpc_funcionaris.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw_funcionaris.id
  }
  tags = {
    Name = "RT Funcionaris"
  }
}

resource "aws_route_table" "rt_seguretat" {
  vpc_id = aws_vpc.vpc_seguretat.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw_seguretat.id
  }
  tags = {
    Name = "RT Seguretat"
  }
}

# Associar les subxarxes a les taules
resource "aws_route_table_association" "assoc_seguretat" {
  subnet_id      = aws_subnet.subnet_seguretat[0].id
  route_table_id = aws_route_table.rt_seguretat.id
}

resource "aws_route_table_association" "assoc_ciutadans" {
  subnet_id      = aws_subnet.subnet_ciutadans[0].id
  route_table_id = aws_route_table.rt_ciutadans.id
}

resource "aws_route_table_association" "assoc_funcionaris" {
  subnet_id      = aws_subnet.subnet_funcionaris[0].id
  route_table_id = aws_route_table.rt_funcionaris.id
}

# Creació de Security Groups
resource "aws_security_group" "sg_ciutadans" {
  vpc_id = aws_vpc.vpc_ciutadans.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
   ingress {
    from_port   = 1194
    to_port     = 1194
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr_block_funcionaris]
  }
  # Regla d'ingrés per permetre el ping ICMP (tipus 8)
  ingress {
    from_port   = 8
    to_port     = 8
    protocol    = "icmp"
    cidr_blocks = [var.vpc_cidr_block_funcionaris]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["84.78.252.65/32"] #ip pública de l'usuari de seguretat
  }
   
   egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "SG Ciutadans"
  }
}

resource "aws_security_group" "sg_funcionaris" {
  vpc_id = aws_vpc.vpc_funcionaris.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
    ingress {
    from_port   = 1194
    to_port     = 1194
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr_block_ciutadans]
  }
  
  # Regla d'ingrés per permetre el ping ICMP (tipus 8)
  ingress {
    from_port   = 8
    to_port     = 8
    protocol    = "icmp"
    cidr_blocks = [var.vpc_cidr_block_ciutadans]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["84.78.252.65/32"] #ip pública de l'usuari de seguretat
  }
   
   egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "SG Funcionaris"
  }
}

resource "aws_security_group" "sg_seguretat" {
  vpc_id = aws_vpc.vpc_seguretat.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["84.78.252.65/32"]  #ip pública de l'usuari de seguretat
  }
  tags = {
    Name = "SG Seguretat"
  }
   egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Configuració de la VPN, la resta es farà manualment a cada ec2
# Connectem les dues vpc per la vpn
resource "aws_vpc_peering_connection" "peering_ciutadans_funcionaris" {
  peer_vpc_id   = aws_vpc.vpc_funcionaris.id
  vpc_id        = aws_vpc.vpc_ciutadans.id
  auto_accept   = true

  tags = {
    Name = "Peering Ciutadans-Funcionaris"
  }
}

# S'afegeix la ruta a la taula d'enrutament de la VPC Ciutadans
resource "aws_route" "ciutadans_to_funcionaris" {
  route_table_id            = aws_route_table.rt_ciutadans.id
  destination_cidr_block    = var.vpc_cidr_block_funcionaris
  vpc_peering_connection_id = "pcx-00546e4a28d13fd12"
}

# S'afegeix la ruta a la taula d'enrutament de la VPC Funcionaris
resource "aws_route" "funcionaris_to_ciutadans" {
  route_table_id            = aws_route_table.rt_funcionaris.id
  destination_cidr_block    = var.vpc_cidr_block_ciutadans
  vpc_peering_connection_id = "pcx-00546e4a28d13fd12"
}
# Permet el trànsit de la VPC Funcionaris cap a la VPC Ciutadans
resource "aws_security_group_rule" "ciutadans_allow_from_funcionaris" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1" # Permet tots els protocols
  cidr_blocks       = [var.vpc_cidr_block_funcionaris]
  security_group_id = aws_security_group.sg_ciutadans.id
}

# Permet el trànsit de la VPC Ciutadans cap a la VPC Funcionaris
resource "aws_security_group_rule" "funcionaris_allow_from_ciutadans" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1" # Permet tots els protocols
  cidr_blocks       = [var.vpc_cidr_block_ciutadans]
  security_group_id = aws_security_group.sg_funcionaris.id
}

# Outputs per compartir informació amb altres mòduls Terraform.
output "sg_ciutadans_id" {
  value = aws_security_group.sg_ciutadans.id
}
output "sg_funcionaris_id" {
  value = aws_security_group.sg_funcionaris.id
}

output "sg_seguretat_id" {
  value = aws_security_group.sg_seguretat.id
}

output "subnet_ciutadans_id" {
  value = aws_subnet.subnet_ciutadans[0].id
  description = "L'identificador de la subxarxa dels ciutadans."
}

output "subnet_funcionaris_id" {
  value = aws_subnet.subnet_funcionaris[0].id
  description = "L'identificador de la subxarxa dels funcionaris."
}

output "subnet_seguretat_id" {
  value = aws_subnet.subnet_seguretat[0].id
  description = "L'identificador de la subxarxa de seguretat."
}

output "vpc_seguretat_id" {
  value       = aws_vpc.vpc_seguretat.id
  description = "ID de la VPC de Seguretat"
}
