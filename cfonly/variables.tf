variable "api" {
  type        = string
  description = "API"
}

variable "idp" {
  type        = string
  description = "Orgin key of Identity Provider"
  default     = null
}

variable "org" {
  type        = string
  description = "org"
}
