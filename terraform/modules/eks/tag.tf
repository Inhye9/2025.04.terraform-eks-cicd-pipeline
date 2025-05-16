# ------------------------------------------------------------------------
# Tag
# ------------------------------------------------------------------------
locals {
  common_tags = {
    CreatedBy = "Terraform"
    Group     = "${var.project_name}-group"
    Owner     = "2244615"
  }

  default_tags = {
    Service = var.project_name 
    Env = var.env
  }
}
