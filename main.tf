locals {
region = lower(var.region)
}

resource "btp_subaccount" "project" {
  name      = "sample project2"
  subdomain = "sampleproject2"
  region    = local.region
}

resource "btp_subaccount_environment_instance" "cloudfoundry" {
  subaccount_id    = btp_subaccount.project.id
  name             = "sample-cf-instance"
  landscape_label  = "cf-${local.region}"
  environment_type = "cloudfoundry"
  service_name     = "cloudfoundry"
  plan_name        = "standard"
  parameters = jsonencode({
    instance_name = "sample-cf-instance"
  })
}

#resource "cloudfoundry_space" "space" {
#  name = "dev_space"
#  org  = btp_subaccount_environment_instance.cloudfoundry.platform_id
#}
