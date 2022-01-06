resource "aws_db_instance" "replicate" {
    instance_class         = "db.t3.micro"
    replicate_source_db = aws_db_instance.rdsInstance.id
    availability_zone = "us-east-1b"
    skip_final_snapshot  = true
}
