resource "btp_subaccount" "project" {
  name      = "sample project1"
  subdomain = "sampleproject1"
  region    = lower(var.region)
}

resource "btp_subaccount_environment_instance" "cloudfoundry" {
  subaccount_id    = btp_subaccount.project.id
  name             = "sample-cf-instance"
  environment_type = "cloudfoundry"
  service_name     = "cloudfoundry"
  plan_name        = "standard"
  parameters = jsonencode({
    instance_name = "sample-cf-instance"
  })
}

resource "cloudfoundry_space" "space" {
  name = "dev_space"
  org  = btp_subaccount_environment_instance.cloudfoundry.platform_id
}
