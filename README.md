# CSYE 6225 assignment 8

# Author: Yingyi Chen

# Install Terraform
https://learn.hashicorp.com/tutorials/terraform/install-cli

# Setup terraform
1. 
create a file named "terraform.tfvars", write required fields to create a module.
An example is like:
{
REGION  = "us-east-1"
VPC     = "192.168.0.0/16"
SUBNET1 = "192.168.1.0/24"
SUBNET2 = "192.168.2.0/24"
SUBNET3 = "192.168.3.0/24"
}

# Apply to AWS
run `terraform fmt`
run `terraform plan`
run `terraform apply`

# Destroy all remote 
run `terraform destroy`
completely destroy the Terraform-managed infrastructure