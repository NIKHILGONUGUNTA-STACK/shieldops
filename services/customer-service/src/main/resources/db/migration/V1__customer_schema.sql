CREATE SCHEMA IF NOT EXISTS customer_data;
CREATE TABLE customer_data.customers (
  id UUID PRIMARY KEY,
  customer_number VARCHAR(40) NOT NULL UNIQUE,
  first_name VARCHAR(80) NOT NULL,
  last_name VARCHAR(80) NOT NULL,
  email VARCHAR(160) NOT NULL UNIQUE,
  country_code CHAR(2) NOT NULL,
  status VARCHAR(20) NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','CLOSED')),
  created_date DATE NOT NULL
);
INSERT INTO customer_data.customers VALUES
('10000000-0000-4000-8000-000000000001','CUST-10001','Alex','Morgan','alex.morgan@example.test','US','ACTIVE','2024-01-15'),
('10000000-0000-4000-8000-000000000002','CUST-10002','Sam','Taylor','sam.taylor@example.test','GB','ACTIVE','2024-03-02'),
('10000000-0000-4000-8000-000000000003','CUST-10003','Jordan','Lee','jordan.lee@example.test','CA','SUSPENDED','2024-05-19');
