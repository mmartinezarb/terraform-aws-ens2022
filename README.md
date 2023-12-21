# terraform-aws-ens2022
Infraestructura AWS gestionada per Terraform dissenyada per complir amb els estàndards de seguretat de l'Esquema Nacional de Seguretat (ENS) 2022

# Terraform AWS ENS2022

Aquest repositori conté configuracions de Terraform per desplegar una infraestructura segura a AWS, conforme amb els requisits de l'Esquema Nacional de Seguretat (ENS) de 2022. Inclou la creació de xarxes VPC, subxarxes, i la configuració de serveis i instàncies EC2, amb un enfocament en la seguretat i millors pràctiques.

## Requeriments

- Terraform v0.12+
- Proveïdor AWS v3.0+
- Credencials d'AWS amb els permisos necessaris

## Instal·lació

Per utilitzar aquestes configuracions:

1. Cloneu aquest repositori.
2. Instal·leu [Terraform](https://www.terraform.io/downloads.html).
3. Creeu un fitxer user_credentials.tfvars amb les credencials d'AWS:
   - `access_key = "access_key"`
   - `secret_key = "secret_key"`
4. Personalitzeu les variables en `variables.tf` segons les vostres necessitats.
5. Inicialitzeu Terraform amb `terraform init -var-file=user_credentials.tfvars`.
6. Apliqueu la configuració amb `terraform apply -var-file=user_credentials.tfvars`.

## Estructura del Repositori

- `main.tf`: Conté la configuració del proveïdor i la definició dels mòduls.
- `variables.tf`: Defineix les variables utilitzades a través del projecte.
- `modules/`: Conté els mòduls de Terraform per a cada component de la infraestructura.
- `Politiques Terrascan/`: Conté diferents polítiques personalitzades de Terrascan.
## Llicència

Aquesta obra està subjecta a una llicència de Reconeixement-NoComercial-SenseObraDerivada 3.0 Espanya de Creative Commons.

## Avisos Legals

Aquest codi s'ofereix tal com és, sense garanties. Encara que està dissenyat per ajudar a complir amb l'ENS 2022, la responsabilitat final de complir amb aquestes normatives és dels usuaris i les seves organitzacions.
