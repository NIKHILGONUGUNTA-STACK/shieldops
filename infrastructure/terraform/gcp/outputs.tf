output "network_name" {
  description = "VPC Network Name"
  value       = google_compute_network.aegis.name
}

output "gke_endpoint" {
  description = "GKE Master Endpoint"
  value       = google_container_cluster.aegis.endpoint
}

output "cloudsql_ip" {
  description = "Cloud SQL Private IP Address"
  value       = google_sql_database_instance.postgres.private_ip_address
}

output "redis_host" {
  description = "Memorystore Redis Private IP"
  value       = google_redis_instance.cache.host
}
