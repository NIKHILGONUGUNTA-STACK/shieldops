variable "project_id" {
  description = "GCP Project Identifier"
  type        = string
}

variable "region" {
  description = "Target GCP deployment region"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment tier"
  type        = string
  default     = "production"
}

variable "gke_cluster_name" {
  description = "GKE cluster identifier"
  type        = string
  default     = "aegis-prod-gke"
}

variable "cloudsql_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-custom-4-16384"
}
