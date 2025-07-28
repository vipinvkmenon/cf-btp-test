variable "globalaccount" {
  type        = string
  description = "The subdomain of the SAP BTP global account."
}

variable "idp" {
  type        = string
  description = "Orgin key of Identity Provider"
  default     = null
}

variable "region" {
  type        = string
  description = "region"
  default     = "ap10"
}