CREATE SCHEMA IF NOT EXISTS transaction_data;
CREATE TABLE transaction_data.beneficiaries (
  id UUID PRIMARY KEY,
  customer_id UUID NOT NULL,
  name VARCHAR(80) NOT NULL,
  destination_account_reference VARCHAR(34) NOT NULL,
  currency VARCHAR(3) NOT NULL,
  status VARCHAR(12) NOT NULL CHECK (status IN ('PENDING','VERIFIED','BLOCKED')),
  created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX beneficiaries_customer_idx ON transaction_data.beneficiaries(customer_id);
CREATE TABLE transaction_data.transactions (
  id UUID PRIMARY KEY,
  reference VARCHAR(80) NOT NULL UNIQUE,
  customer_id UUID NOT NULL,
  source_account_id UUID NOT NULL,
  beneficiary_id UUID NOT NULL REFERENCES transaction_data.beneficiaries(id),
  amount DECIMAL(19,4) NOT NULL CHECK (amount > 0),
  currency VARCHAR(3) NOT NULL,
  status VARCHAR(12) NOT NULL CHECK (status IN ('CREATED','PENDING','AUTHORIZED','COMPLETED','FAILED','CANCELLED','REVERSED')),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX transactions_customer_created_idx ON transaction_data.transactions(customer_id,created_at DESC);
