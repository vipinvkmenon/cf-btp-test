terraform {
  required_providers {
    btp = {
      source  = "sap/btp"
      version = "~> 1.15.1"
    }
    cloudfoundry = {
      source  = "cloudfoundry/cloudfoundry"
      version = "~> 1.8.0"
    }
  }
}

provider "cloudfoundry" {
  api_url = var.api
  origin  = var.idp
}
