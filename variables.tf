variable "REGION" {}
variable "PROFILE" {}
variable "VPC" {}
variable "VPCname" {}

//subnet cidr
variable "SUBNET1" {}
variable "SUBNET2" {}
variable "SUBNET3" {}

//subnet name
variable "SUBNET1name" {}
variable "SUBNET2name" {}
variable "SUBNET3name" {}

variable "IGWname" {}
variable "RouteCidr" {}
variable "RTname" {}

//security for application
variable "applicationSecName" {}
//change to port 80
//variable "appPort" {}

//security for database
variable "databaseSecName" {}
variable "databasePort" {}
//variable "cidrDataSec" {}

//S3 Bucket
variable "days" {}
variable "storageClass" {}
variable "s3Algorithm" {}

//RDS parameter group
variable "RDSparaGroupname" {}
variable "RDSparaGroupFamilyname" {}

//RDS instance subnet group
variable "rdsSubnetGroup" {}

//RDS instance
variable "dbEngine" {}
variable "dbEngineVersion" {}
variable "dbInstanceClass" {}
variable "dbIdentifier" {}
variable "dbUsername" {}
variable "dbPassword" {}
//variable "dbHost" {}
variable "dbPort" {}
variable "dbName" {}
variable "allocatedStorage" {}

variable "AWSaccountID" {}

//key pair
//variable "keyPairname" {}
//variable "keyPublic" {}

//EC2 instance
variable "ec2InstanceType" {}
variable "ebsName" {}
variable "ebsVolumeSize" {}
variable "ebsVolumeType" {}
variable "ec2Name" {}



//iam role
variable "iamRoleName" {}

//create a profile for Webapp EC2
variable "ec2profile" {}

//route 53

variable "codeDeployappComputePlatform" {}
variable "codeDeployappName" {}
variable "codeDeployDGname" {}

//dynamoDB
variable "tableName" {}

//assignment8
variable "dev_certification_arn" {}
variable "prod_certification_arn" {}


