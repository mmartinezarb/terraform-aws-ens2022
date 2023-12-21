# Configuració del proveïdor AWS amb claus d'accés i regió.
provider "aws" {
  access_key = var.access_key
  secret_key = var.secret_key
  region = var.region
}
# Mòdul per crear la xarxa VPC amb subxarxes específiques.
module "xarxa" {
  source        = "./modules/xarxa"
  vpc_cidr_block_ciutadans       = "10.0.1.0/24"
  vpc_cidr_block_funcionaris     = "10.0.2.0/24"
  vpc_cidr_block_seguretat = "10.0.3.0/24"
  create_subnet_ciutadans      = true
  subnet_ciutadans_cidr_block  = "10.0.1.0/24"
  create_subnet_funcionaris      = true
  subnet_funcionaris_cidr_block  = "10.0.2.0/24"
  create_subnet_seguretat      = true
  subnet_seguretat_cidr_block  = "10.0.3.0/24"
  ec2_ciutadans_id = module.instancies.ec2_ciutadans_id
}
# Mòdul per configurar els diferents serveis amb els recursos creats en el mòdul 'xarxa'.
module "serveis" {
  source        = "./modules/serveis"
  vpc_id = module.xarxa.vpc_seguretat_id
  cloudwatch_agent_role_arn   = module.iam.cloudwatch_agent_role_arn
  cloudwatch_agent_role_name = module.iam.cloudwatch_agent_role_name
}
# Mòdul per crear instàncies EC2 en les subxarxes definides al mòdul 'xarxa'.
module "instancies" {
  source        = "./modules/instancies"
  ami_id        = var.ami_id
  instance_type = var.instance_type
  subnet_ciutadans_id   = module.xarxa.subnet_ciutadans_id
  subnet_funcionaris_id   = module.xarxa.subnet_funcionaris_id
  subnet_seguretat_id   = module.xarxa.subnet_seguretat_id
  sg_ciutadans_id = module.xarxa.sg_ciutadans_id
  sg_funcionaris_id = module.xarxa.sg_funcionaris_id
  sg_seguretat_id = module.xarxa.sg_seguretat_id
  cloudwatch_agent_instance_profile_name = module.iam.cloudwatch_agent_instance_profile_name
}
# Mòdul per gestionar els recursos IAM relacionats amb les instàncies EC2.
module "iam" {
  source        = "./modules/iam"
  ciutadans_instance_arn = module.instancies.ciutadans_instance_arn
  funcionaris_instance_arn = module.instancies.funcionaris_instance_arn
}

