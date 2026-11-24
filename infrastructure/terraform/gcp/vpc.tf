# GCP VPC Network with secondary subnet IP ranges for GKE pods and services
resource "google_compute_network" "aegis" {
  name                    = "aegis-${var.environment}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "aegis" {
  name          = "aegis-${var.environment}-subnet"
  ip_cidr_range = "10.10.0.0/20"
  region        = var.region
  network       = google_compute_network.aegis.id

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.20.0.0/16"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.30.0.0/20"
  }

  private_ip_google_access = true
}

# Private Service Connection for Cloud SQL and Memorystore
resource "google_compute_global_address" "private_ip_alloc" {
  name          = "aegis-${var.environment}-private-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.aegis.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.aegis.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_alloc.name]
}
