resource "aws_vpc" "VPC" {
  cidr_block                       = var.VPC
  instance_tenancy                 = "default"
  enable_dns_hostnames             = true
  enable_dns_support               = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false
  tags = {
    Name = "${var.VPCname}"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "subnet1" {
  vpc_id            = aws_vpc.VPC.id
  cidr_block        = var.SUBNET1
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = {
    Name = "${var.SUBNET1name}"
  }
}

resource "aws_subnet" "subnet2" {
  vpc_id            = aws_vpc.VPC.id
  cidr_block        = var.SUBNET2
  availability_zone = data.aws_availability_zones.available.names[1]
  tags = {
    Name = "${var.SUBNET2name}"
  }
}

resource "aws_subnet" "subnet3" {
  vpc_id            = aws_vpc.VPC.id
  cidr_block        = var.SUBNET3
  availability_zone = data.aws_availability_zones.available.names[2]
  tags = {
    Name = "${var.SUBNET3name}"
  }
}


resource "aws_internet_gateway" "internetGateway" {
  vpc_id = aws_vpc.VPC.id
  tags = {
    Name = "${var.IGWname}"
  }
}

resource "aws_route_table" "routeTable" {
  vpc_id = aws_vpc.VPC.id
  route {
    cidr_block = var.RouteCidr
    gateway_id = aws_internet_gateway.internetGateway.id
  }
  tags = {
    Name = "${var.RTname}"
  }
}

resource "aws_route_table_association" "subnetroute1" {
  subnet_id      = aws_subnet.subnet1.id
  route_table_id = aws_route_table.routeTable.id
}

resource "aws_route_table_association" "subnetroute2" {
  subnet_id      = aws_subnet.subnet2.id
  route_table_id = aws_route_table.routeTable.id
}

resource "aws_route_table_association" "subnetroute3" {
  subnet_id      = aws_subnet.subnet3.id
  route_table_id = aws_route_table.routeTable.id
}

resource "aws_security_group" "applicationSec" {
  name   = var.applicationSecName
  vpc_id = aws_vpc.VPC.id

  //change to port 80
  // ingress {
  //   from_port   = var.appPort
  //   to_port     = var.appPort
  //   protocol    = "tcp"
  //   cidr_blocks = ["0.0.0.0/0"]
  // }

  // ingress {
  //   from_port   = 22
  //   to_port     = 22
  //   protocol    = "tcp"
  //   cidr_blocks = ["0.0.0.0/0"]
  // }

  // ingress {
  //   from_port   = 80
  //   to_port     = 80
  //   protocol    = "tcp"
  //   //cidr_blocks = [aws_vpc.VPC.cidr_block]
  //   security_groups = ["${aws_security_group.loadBalanceSec.id}"]

  // }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    // cidr_blocks = [aws_vpc.VPC.cidr_block]
    security_groups = ["${aws_security_group.loadBalanceSec.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_security_group" "databaseSec" {

  name   = var.databaseSecName
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port       = var.databasePort
    to_port         = var.databasePort
    protocol        = "tcp"
    security_groups = ["${aws_security_group.applicationSec.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}


resource "aws_s3_bucket" "s3bucket" {
  bucket = "pictures.${var.PROFILE}.yingyi.me"
  acl    = "private"

  force_destroy = true

  lifecycle_rule {
    enabled = true
    transition {
      days          = var.days
      storage_class = var.storageClass
    }
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = var.s3Algorithm
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "publicAccessBlockS3" {
  bucket             = aws_s3_bucket.s3bucket.id
  ignore_public_acls = true
}

resource "aws_db_subnet_group" "RDSsubnetGroup" {
  name       = var.rdsSubnetGroup
  subnet_ids = [aws_subnet.subnet1.id, aws_subnet.subnet2.id, aws_subnet.subnet3.id]
}

resource "aws_db_parameter_group" "RDSparameterGroup" {
  name   = var.RDSparaGroupname
  family = var.RDSparaGroupFamilyname
  parameter {
    name  = "performance_schema"
    value = "1"
    apply_method = "pending-reboot"
  }
}

resource "aws_db_instance" "rdsInstance" {
  engine         = var.dbEngine
  engine_version = var.dbEngineVersion
  instance_class = var.dbInstanceClass
  multi_az       = false
  identifier     = var.dbIdentifier
  username       = var.dbUsername
  password       = var.dbPassword

  availability_zone = "us-east-1a"
  backup_retention_period= 1


  port = var.dbPort


  db_subnet_group_name = aws_db_subnet_group.RDSsubnetGroup.name
  publicly_accessible  = false
  name                 = var.dbName

  vpc_security_group_ids = [aws_security_group.databaseSec.id]

  allocated_storage = var.allocatedStorage

  storage_encrypted = true
  kms_key_id = aws_kms_key.rdskey.arn

  parameter_group_name = aws_db_parameter_group.RDSparameterGroup.name
  skip_final_snapshot  = true
}

data "aws_ami" "amiAWS" {
  most_recent = true
  owners      = ["${var.AWSaccountID}"]
}


##can be delete
// resource "aws_instance" "ec2Instance" {
//   ami           = data.aws_ami.amiAWS.image_id
//   instance_type = var.ec2InstanceType

//   disable_api_termination = false

//   iam_instance_profile = aws_iam_instance_profile.ec2_codedeploy_profile.name

//   ebs_block_device {
//     device_name           = var.ebsName
//     volume_size           = var.ebsVolumeSize
//     volume_type           = var.ebsVolumeType
//     delete_on_termination = "true"
//   }

//   vpc_security_group_ids = [aws_security_group.applicationSec.id]

//   subnet_id = aws_subnet.subnet1.id

//   associate_public_ip_address = true

//   user_data = <<EOF
// #! /bin/bash
// sudo mkdir /home/ubuntu/webapp/
// sudo chmod -R 777 /home/ubuntu/webapp
// echo -e "DB_HOST = ${aws_db_instance.rdsInstance.address}" >> /home/ubuntu/webapp/.env
// echo -e "DB_NAME = ${aws_db_instance.rdsInstance.name}" >> /home/ubuntu/webapp/.env
// echo -e "DB_USERNAME = ${aws_db_instance.rdsInstance.username}" >> /home/ubuntu/webapp/.env
// echo -e "DB_PASSWORD = ${aws_db_instance.rdsInstance.password}" >> /home/ubuntu/webapp/.env
// echo -e "S3_BUCKET= ${aws_s3_bucket.s3bucket.bucket}" >> /home/ubuntu/webapp/.env
// EOF

//   key_name = "csyekey"

//   tags = {
//     Name = "${var.ec2Name}"
//   }
//   depends_on = [
//     aws_s3_bucket.s3bucket,
//     aws_db_instance.rdsInstance,
//     aws_iam_instance_profile.ec2Profile
//   ]
// }



//iam role for ec2 to pass pictures to S3
resource "aws_iam_role" "EC2-CSYE6225" {
  name = var.iamRoleName
  assume_role_policy = jsonencode(
    {
      Version : "2012-10-17"
      Statement : [
        {
          Action : "sts:AssumeRole"
          Effect : "Allow"
          Sid : ""
          Principal : {
            Service : "ec2.amazonaws.com"
          }
        },
      ]
    }
  )
  tags = {
    name = "${var.iamRoleName}"
  }
}

//iam attachment for ec2 to pass pictures to S3
resource "aws_iam_role_policy_attachment" "attachRoletoEc2" {
  role       = aws_iam_role.EC2-CSYE6225.name
  policy_arn = aws_iam_policy.WebAppS32.arn
}

//create a profile for Webapp to S3
resource "aws_iam_instance_profile" "ec2Profile" {
  name = var.ec2profile
  role = aws_iam_role.EC2-CSYE6225.name
}



resource "aws_iam_instance_profile" "ec2_codedeploy_profile" {
  name = "ec2_codedeploy_profile2"
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}


#Assignment5 DNS part
data "aws_route53_zone" "selected" {
  name         = "${var.PROFILE}.yingyi.me"
  private_zone = false
}

resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = "${var.PROFILE}.yingyi.me"
  type    = "A"
  alias {
    name                   = aws_lb.webapp_lb.dns_name
    zone_id                = aws_lb.webapp_lb.zone_id
    evaluate_target_health = true
  }
}


#CodeDeploy-EC2-S3 policy for the Server(EC2)
resource "aws_iam_policy" "CodeDeploy-EC2-S3" {
  name = "CodeDeploy-EC2-S3"

  policy = jsonencode(
    {
      "Version" : "2012-10-17"
      "Statement" : [
        {
          "Action" : [
            "s3:Get*",
            "s3:List*"
          ],
          "Effect" : "Allow",
          "Resource" : ["arn:aws:s3:::codedeploy.${var.PROFILE}.yingyi.me/*",
                        "arn:aws:s3:::codedeploy.${var.PROFILE}.yingyi.me"]

        },
      ]
    }
  )
}

#codedeploy role: CodeDeployEC2ServiceROoe for EC2 Instance
resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"
  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Action" : "sts:AssumeRole",
          "Principal" : {
            "Service" : "ec2.amazonaws.com"
          },
          "Effect" : "Allow",
          "Sid" : ""
        }
      ],
    }
  )

  tags = {
    Name = "CodeDeployEC2ServiceRole"
  }
}

#CodeDeployEC2ServiceRole_CodeDeploy-EC2-S3 attachment
resource "aws_iam_role_policy_attachment" "CodeDeployEC2ServiceRole_CodeDeploy-EC2-S3" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.CodeDeploy-EC2-S3.arn
}

#iam policy for ec2 to pass pictures to S3
resource "aws_iam_policy" "WebAppS32" {
  name = "WebAppS32"
  policy = jsonencode(
    {
      Version : "2012-10-17"
      Statement : [
        {
          Effect : "Allow"
          Action : [
            "s3:PutObject",
            "s3:GetObject",
            "s3:DeleteObject",
            "s3:PutObjectAcl"
          ]
          Resource : [
            "arn:aws:s3:::${aws_s3_bucket.s3bucket.bucket}",
            "arn:aws:s3:::${aws_s3_bucket.s3bucket.bucket}/*"
          ]
        },
      ]
    }
  )
}

#elastic load balancing policy
resource "aws_iam_policy" "LoadbalancePolicy" {
  name = "LoadbalancePolicy"
  policy = jsonencode(
    {
      Version : "2012-10-17"
      Statement : [
        {
          Effect : "Allow"
          Action : [
                "elasticloadbalancing:DeregisterTargets",
                "elasticloadbalancing:RegisterTargets"
          ]
          Resource : [
            "*"
            
          ]
        }
      ],
      "Version": "2012-10-17"
    }
  )
}

#load balancing policy attachment
resource "aws_iam_role_policy_attachment" "CodeDeployEC2ServiceRole_LoadbalancePolicy" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.LoadbalancePolicy.arn
}


#CodeDeployEC2ServiceRole_WebAppS32 attachment
resource "aws_iam_role_policy_attachment" "CodeDeployEC2ServiceRole_WebAppS3" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.WebAppS32.arn
}

#codedeploy role: CodeDeployServiceRole for EC2 Instance
resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"
  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17"
      "Statement" : [
        {
          "Action" : "sts:AssumeRole",
          "Principal" : {
            "Service" : "codedeploy.amazonaws.com"
          },
          "Effect" : "Allow"
          "Sid" : ""
        }
      ],
    }
  )
  tags = {
    Name = "CodeDeployServiceRole"
  }
}

#CodeDeployServiceRole_AWSCodeDeployRole attachment
resource "aws_iam_role_policy_attachment" "CodeDeployServiceRole_AWSCodeDeployRole" {
  role       = aws_iam_role.CodeDeployServiceRole.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
}



#CodeDeploy app
resource "aws_codedeploy_app" "CodeDeployApp" {
  compute_platform = var.codeDeployappComputePlatform
  name             = var.codeDeployappName
}

#CodeDeploy Deployment Group
resource "aws_codedeploy_deployment_group" "CodeDeployDG" {
  app_name               = aws_codedeploy_app.CodeDeployApp.name
  deployment_group_name  = var.codeDeployDGname
  service_role_arn       = aws_iam_role.CodeDeployServiceRole.arn
  deployment_config_name = "CodeDeployDefault.AllAtOnce"

  deployment_style {
    deployment_type = "IN_PLACE"
  }

  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = var.ec2Name
    }
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

  autoscaling_groups    = ["${aws_autoscaling_group.autoScalingGroup.name}"]
}


#assignment6

resource "aws_iam_policy" "CloudWatchAgentPolicy" {
  name = "CloudWatchAgentPolicy"

  policy = jsonencode(
    {
      "Version" : "2012-10-17"
      "Statement" : [
        {
          "Action" : [
                "cloudwatch:PutMetricData",
                "ec2:DescribeTags",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups",
                "logs:CreateLogStream",
                "logs:CreateLogGroup"
          ],
          "Effect" : "Allow",
          "Resource" : "*",
        },
                {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter",
                "ssm:PutParameter"
            ],
            "Resource": "arn:aws:ssm:${var.REGION}:${var.AWSaccountID}:parameter/AmazonCloudWatch-*"
        }
      ]
    }
  )
}

#attach role to CloudWatch policy
resource "aws_iam_role_policy_attachment" "EC2CloudWatchAttachment" {
  role       =  aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.CloudWatchAgentPolicy.arn
}

#Auto scaling
resource "aws_launch_configuration" "asg_launch_config" {
  image_id             = data.aws_ami.amiAWS.image_id 
  name                 = "asg_launch_config"
  instance_type        = "t2.micro"
  iam_instance_profile = aws_iam_instance_profile.ec2_codedeploy_profile.name
  key_name="csyekey"
  security_groups= ["${aws_security_group.applicationSec.id}"]

  root_block_device {
    // device_name           = var.ebsName
    // volume_size           = var.ebsVolumeSize
    // volume_type           = var.ebsVolumeType
    // delete_on_termination = "true"
    encrypted = true
  }

  user_data = <<EOF
#! /bin/bash
sudo mkdir /home/ubuntu/webapp/
sudo chmod -R 777 /home/ubuntu/webapp
echo -e "DB_HOST = ${aws_db_instance.rdsInstance.address}" >> /home/ubuntu/webapp/.env
echo -e "DB_HOST2 = ${aws_db_instance.replicate.address}" >> /home/ubuntu/webapp/.env
echo -e "DB_NAME = ${aws_db_instance.rdsInstance.name}" >> /home/ubuntu/webapp/.env
echo -e "DB_USERNAME = ${aws_db_instance.rdsInstance.username}" >> /home/ubuntu/webapp/.env
echo -e "DB_PASSWORD = ${aws_db_instance.rdsInstance.password}" >> /home/ubuntu/webapp/.env
echo -e "S3_BUCKET= ${aws_s3_bucket.s3bucket.bucket}" >> /home/ubuntu/webapp/.env
echo -e "ENV= ${var.PROFILE}" >> /home/ubuntu/webapp/.env
echo -e "TOPICARN= ${aws_sns_topic.user_updates.arn}" >> /home/ubuntu/webapp/.env
echo -e "{
    \"agent\": {
        \"metrics_collection_interval\": 10,
        \"logfile\": \"/var/logs/amazon-cloudwatch-agent.log\"
    },
    \"logs\": {
        \"logs_collected\": {
            \"files\": {
                \"collect_list\": [
                    {
                        \"file_path\": \"/var/log/cloud-init-output.log\",
                        \"log_group_name\": \"csye6225\",
                        \"log_stream_name\": \"instance-begin\"
                    }
                ]
            }
        },
        \"log_stream_name\": \"cloudwatch_log_stream\"
    }
}" >> /home/ubuntu/init_cloudwatch.json
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/home/ubuntu/init_cloudwatch.json
echo -e "${aws_lb_target_group.load-balance-target-group.arn}" >> /home/ubuntu/lb_arn
EOF

    
associate_public_ip_address = "true"

  depends_on = [
    aws_s3_bucket.s3bucket,
    aws_db_instance.rdsInstance,
    aws_iam_instance_profile.ec2Profile
  ]
}

resource "aws_autoscaling_group" "autoScalingGroup" {
  name                 = "asg-webapp"
  launch_configuration = aws_launch_configuration.asg_launch_config.name
  min_size             = 3
  max_size             = 5
  desired_capacity     = 3
  default_cooldown     = 600
  vpc_zone_identifier  = ["${aws_subnet.subnet1.id}","${aws_subnet.subnet2.id}","${aws_subnet.subnet3.id}"]
  target_group_arns    = ["${aws_lb_target_group.load-balance-target-group.arn}"]
  tag {
    key                 = "Name"
    value               = "${var.ec2Name}"
    propagate_at_launch = true
  }


  lifecycle {
    create_before_destroy = true
  }
}


resource "aws_autoscaling_policy" "scaleUp" {
  name                   = "agents-scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.autoScalingGroup.name
}

resource "aws_autoscaling_policy" "scaleDown" {
  name                   = "agents-scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.autoScalingGroup.name
}

resource "aws_cloudwatch_metric_alarm" "CPU-high" {
  alarm_name          = "mem-util-high-agents"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "5"
  alarm_description   = "This metric monitors ec2 CPU for high utilization on agent hosts"
  alarm_actions = [
    "${aws_autoscaling_policy.scaleUp.arn}"
  ]
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.autoScalingGroup.name}"
  }
}

resource "aws_cloudwatch_metric_alarm" "CPU-low" {
  alarm_name          = "mem-util-low-agents"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "3"
  alarm_description   = "This metric monitors ec2 CPU for low utilization on agent hosts"
  alarm_actions = [
    "${aws_autoscaling_policy.scaleDown.arn}"
  ]
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.autoScalingGroup.name}"
  }
}

#load balancer
resource "aws_lb_target_group" "load-balance-target-group" {
  name     = "load-balance-target-group"
  port     = "80"
  protocol = "HTTP"
  vpc_id   = aws_vpc.VPC.id
}

resource "aws_lb" "webapp_lb" {
  name               = "webapp-lb"
  subnets            = ["${aws_subnet.subnet1.id}", "${aws_subnet.subnet2.id}", "${aws_subnet.subnet3.id}"]
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.loadBalanceSec.id}"]

}

resource "aws_lb_listener" "lb-Listener" {
  //depends_on = ["aws_lb.webapp_lb.id", "aws_lb_target_group.load-balance-target-group.id"]
  load_balancer_arn = aws_lb.webapp_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.PROFILE == "dev" ? "${var.dev_certification_arn}" : "${var.prod_certification_arn}"

  default_action {
    target_group_arn = aws_lb_target_group.load-balance-target-group.arn
    type             = "forward"
  }
}

resource "aws_security_group" "loadBalanceSec" {
  name   = "loadBalanceSec"
  vpc_id = aws_vpc.VPC.id

  // ingress {
  //   from_port   = 22
  //   to_port     = 22
  //   protocol    = "tcp"
  //   cidr_blocks = ["0.0.0.0/0"]
  // }

  // ingress {
  //   from_port   = 80
  //   to_port     = 80
  //   protocol    = "tcp"
  //   cidr_blocks = ["0.0.0.0/0"]

  // }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}


//assignment7 dynamodb
resource "aws_iam_role_policy_attachment" "CodeDeployEC2ServiceRole_dynamodbPolicy" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.DynamoDB_for_CodeDeployEC2Service_Policy.arn
}

resource "aws_iam_policy" "DynamoDB_for_CodeDeployEC2Service_Policy" {
  name = "DynamoDB_for_CodeDeployEC2Service_Policy"

  policy = jsonencode(
    {
      "Version" : "2012-10-17"
      "Statement" : [
        {
          "Action" : [
            "dynamodb:List*",
            "dynamodb:DescribeLimits",
            "dynamodb:BatchGet*",
            "dynamodb:DescribeStream",
            "dynamodb:DescribeTable",
            "dynamodb:DescribeTimeToLive",
            "dynamodb:Get*",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:BatchWrite*",
            "dynamodb:CreateTable",
            "dynamodb:Delete*",
            "dynamodb:Update*",
            "dynamodb:PutItem"
          ],
          "Effect" : "Allow",
          "Resource" : ["arn:aws:dynamodb:${var.REGION}:${var.AWSaccountID}:table/${var.tableName}/*",
                        "arn:aws:dynamodb:${var.REGION}:${var.AWSaccountID}:table/${var.tableName}"]
        }
      ]
    }
  )
}

///assignment8
// resource "aws_ebs_volume" "ebsvolume" {
//   availability_zone = "us-east-1a"
//   size              = "${var.ebsVolumeSize}"
//   type              = "${var.ebsVolumeType}"
//   encrypted = true
//   kms_key_id = aws_kms_key.ebskey.arn
// }

resource "aws_kms_key" "rdskey" {
  description             = "KMS key for RDS"
  deletion_window_in_days = 10
}

resource "aws_kms_key" "ebskey" {
  description             = "KMS key for EBS "
  deletion_window_in_days = 10
  policy = <<EOF
  {
    "Id": "key-consolepolicy-3",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${var.AWSaccountID}:root"
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow access for Key Administrators",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::${var.AWSaccountID}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                    "arn:aws:iam::${var.AWSaccountID}:user/ghactions-app",
                    "arn:aws:iam::${var.AWSaccountID}:user/ghactions-ami"
                ]
            },
            "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:TagResource",
                "kms:UntagResource",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow use of the key",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${var.AWSaccountID}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow attachment of persistent resources",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${var.AWSaccountID}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            },
            "Action": [
                "kms:CreateGrant",
                "kms:ListGrants",
                "kms:RevokeGrant"
            ],
            "Resource": "*",
            "Condition": {
                "Bool": {
                    "kms:GrantIsForAWSResource": "true"
                }
            }
        }
    ]
}
  EOF
}

resource "aws_ebs_default_kms_key" "ebs_default_kms_key" {
  key_arn = aws_kms_key.ebskey.arn
}

resource "aws_ebs_encryption_by_default" "ebs_encryption_by_default" {
  enabled = true
}