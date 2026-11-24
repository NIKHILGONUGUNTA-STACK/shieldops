# Cloud SQL for PostgreSQL High Availability Instance
resource "google_sql_database_instance" "postgres" {
  name             = "aegis-${var.environment}-db"
  database_version = "POSTGRES_17"
  region           = var.region

  depends_on = [google_service_networking_connection.private_vpc_connection]

  settings {
    tier              = var.cloudsql_tier
    availability_type = "REGIONAL"
    disk_size         = 100
    disk_type         = "PD_SSD"
    disk_autoresize   = true

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.aegis.id
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
    }
  }
  deletion_protection = true
}

resource "google_sql_database" "aegis_db" {
  name     = "aegis"
  instance = google_sql_database_instance.postgres.name
}

resource "google_sql_database" "keycloak_db" {
  name     = "keycloak"
  instance = google_sql_database_instance.postgres.name
}
