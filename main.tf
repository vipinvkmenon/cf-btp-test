locals {
region = lower(var.region)
ts = formatdate("YYYYMMDDhhmmss", timestamp())
}

resource "btp_subaccount" "project" {
  name      = "github-jwt-workflow-created-${local.ts}"
  subdomain = "githubjwtcreated${local.ts}"
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
    instance_name = "-cf-instance-${local.ts}"
  })
}

#resource "cloudfoundry_space" "space" {
#  name = "dev_space"
#  org  = btp_subaccount_environment_instance.cloudfoundry.platform_id
#}
