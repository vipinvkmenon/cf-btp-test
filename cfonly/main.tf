data "cloudfoundry_org" "org" {
  name = var.org
}

resource "cloudfoundry_space" "spacei" {
  name      = "space"
  org       = data.cloudfoundry_org.org.id
  allow_ssh = "true"
  labels    = { test : "pass", purpose : "prod" }
}
