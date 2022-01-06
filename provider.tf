terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "3.52"
    }
  }
}

provider "aws" {
  region  = var.REGION
  profile = var.PROFILE
}