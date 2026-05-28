BEGIN;

CREATE SCHEMA IF NOT EXISTS cu;

CREATE SCHEMA IF NOT EXISTS ext;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" SCHEMA ext;

CREATE OR REPLACE FUNCTION cu.uuid_new()
RETURNS UUID
LANGUAGE SQL
AS $$
    SELECT ext.uuid_generate_v4();
$$;

CREATE TABLE IF NOT EXISTS cu.account (
	id         UUID NOT NULL DEFAULT cu.uuid_new(),
        name       TEXT NOT NULL,
        username   TEXT NOT NULL,
        password   TEXT NOT NULL,
        valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        valid_to   TIMESTAMPTZ,
        valid_id   UUID NOT NULL DEFAULT cu.uuid_new(),
        CONSTRAINT account_pk PRIMARY KEY (id),
        CONSTRAINT ck_valid   CHECK (valid_from < valid_to)
);

CREATE UNIQUE INDEX account_ux_username
ON cu.account (username)
WHERE valid_to IS NULL;

CREATE UNIQUE INDEX account_ux_valid
ON cu.account (valid_id)
WHERE valid_to IS NULL;

CREATE TABLE IF NOT EXISTS cu.session (
	id UUID NOT NULL DEFAULT cu.uuid_new(),
        account_id UUID NOT NULL,
        login_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        logout_at TIMESTAMPTZ,
        CONSTRAINT session_pk PRIMARY KEY (id),
        CONSTRAINT fk_account FOREIGN KEY (account_id) REFERENCES cu.account (id)
);

INSERT INTO cu.account (name, username, password)
VALUES ('Elefante do PostgreSQL', 'psql', 'postgres');

COMMIT;
