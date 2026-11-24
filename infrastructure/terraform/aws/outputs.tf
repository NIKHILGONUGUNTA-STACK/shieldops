output "vpc_id" {
  description = "VPC Identifier"
  value       = aws_vpc.aegis.id
}

output "eks_cluster_name" {
  description = "EKS Cluster Name"
  value       = aws_eks_cluster.aegis.name
}

output "eks_cluster_endpoint" {
  description = "EKS Control Plane Endpoint"
  value       = aws_eks_cluster.aegis.endpoint
}

output "rds_endpoint" {
  description = "PostgreSQL Connection Endpoint"
  value       = aws_db_instance.postgres.endpoint
}

output "redis_primary_endpoint" {
  description = "ElastiCache Redis Primary Endpoint"
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
}
