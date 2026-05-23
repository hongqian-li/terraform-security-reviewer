resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

resource "aws_ebs_volume" "my_volume" {
  availability_zone = "us-east-1a"
  size              = 40
  # encrypted not set
}

resource "aws_security_group" "allow_all" {
  name = "allow_all"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "mydb" {
  engine   = "mysql"
  password = "SuperSecret123!"
}
