# RDS PostgreSQL Multi-AZ Production Instance
resource "aws_db_subnet_group" "rds" {
  name       = "aegis-${var.environment}-db-subnet"
  subnet_ids = aws_subnet.database[*].id

  tags = {
    Name = "aegis-${var.environment}-db-subnet"
  }
}

resource "aws_security_group" "rds" {
  name        = "aegis-${var.environment}-rds-sg"
  description = "Access to RDS PostgreSQL from EKS nodes"
  vpc_id      = aws_vpc.aegis.id

  ingress {
    description = "PostgreSQL access from EKS private subnets"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = aws_subnet.private[*].cidr_block
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "postgres" {
  identifier                  = "aegis-${var.environment}-db"
  allocated_storage           = var.rds_allocated_storage
  max_allocated_storage       = 500
  engine                      = "postgres"
  engine_version              = "17.1"
  instance_class              = var.rds_instance_class
  db_name                     = "aegis"
  username                    = "aegis_admin"
  manage_master_user_password = true
  multi_az                    = true
  storage_type                = "gp3"
  storage_encrypted           = true
  deletion_protection         = true
  skip_final_snapshot         = false
  final_snapshot_identifier   = "aegis-db-final-snapshot"

  db_subnet_group_name   = aws_db_subnet_group.rds.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  backup_retention_period = 30
  backup_window           = "03:00-04:00"
  maintenance_window      = "Sun:04:30-Sun:05:30"
}
