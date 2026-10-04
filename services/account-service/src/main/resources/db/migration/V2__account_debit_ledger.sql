CREATE TABLE account_data.account_debits (
 id UUID PRIMARY KEY, reference VARCHAR(80) NOT NULL UNIQUE, account_id UUID NOT NULL REFERENCES account_data.accounts(id),
 amount DECIMAL(19,4) NOT NULL CHECK (amount > 0), currency VARCHAR(3) NOT NULL, created_at TIMESTAMPTZ NOT NULL
);
