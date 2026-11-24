# ElastiCache Redis Cluster for Telemetry & Stream Ingestion
resource "aws_elasticache_subnet_group" "redis" {
  name       = "aegis-${var.environment}-redis-subnets"
  subnet_ids = aws_subnet.database[*].id
}

resource "aws_security_group" "redis" {
  name        = "aegis-${var.environment}-redis-sg"
  description = "Allow Redis traffic from EKS worker nodes"
  vpc_id      = aws_vpc.aegis.id

  ingress {
    description = "Redis from EKS compute tier"
    from_port   = 6379
    to_port     = 6379
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

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "aegis-${var.environment}-cache"
  description                = "Aegis Out-of-Band Telemetry Stream Buffer"
  node_type                  = var.redis_node_type
  num_cache_clusters         = 3
  port                       = 6379
  parameter_group_name       = "default.redis7"
  subnet_group_name          = aws_elasticache_subnet_group.redis.name
  security_group_ids         = [aws_security_group.redis.id]
  automatic_failover_enabled = true
  multi_az_enabled           = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
}
