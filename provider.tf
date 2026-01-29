terraform {
  required_providers {
    btp = {
      source  = "sap/btp"
      version = "~> 1.18.1"
    }
    cloudfoundry = {
      source  = "cloudfoundry/cloudfoundry"
      version = "~> 1.8.0"
    }
  }
}

provider "btp" {
globalaccount = var.globalaccount
  idp           = var.idp
}
provider "cloudfoundry" {
  api_url = "https://api.cf.${var.region}.hana.ondemand.com"
  origin  = var.idp
}
