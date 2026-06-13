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

CREATE TYPE cu.course_modality AS ENUM (
	'bachelor',
	'teaching',
	'teaching_2',
	'technology'
);

CREATE TABLE IF NOT EXISTS cu.course (
	id         UUID NOT NULL DEFAULT cu.uuid_new(),
	name       TEXT NOT NULL,
	modality   cu.course_modality NOT NULL,
	valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	valid_to   TIMESTAMPTZ,
	valid_id   UUID NOT NULL DEFAULT cu.uuid_new(),
	CONSTRAINT course_pk PRIMARY KEY (id),
	CONSTRAINT ck_valid  CHECK (valid_from < valid_to)
);

CREATE UNIQUE INDEX course_ux
ON cu.course (name, modality)
WHERE valid_to IS NULL;

CREATE UNIQUE INDEX course_ux_valid
ON cu.course (valid_id)
WHERE valid_to IS NULL;

INSERT INTO cu.course (name, modality)
VALUES
	('Administração', 'bachelor'),
	('Educação Especial Inclusiva', 'teaching_2'),
	('Letras - Inglês', 'teaching'),
	('Matemática', 'teaching'),
	('Sistemas de Informação', 'bachelor'),
	('Turismo e Negócio', 'bachelor');

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

CREATE TYPE cu.chat_kind AS ENUM (
	'direct',
	'group'
);

CREATE TABLE cu.chat (
	id          UUID NOT NULL DEFAULT cu.uuid_new(),
	kind        cu.chat_kind NOT NULL,
	name        TEXT NOT NULL,
	description TEXT,
	valid_from  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	valid_to    TIMESTAMPTZ,
	valid_id    UUID NOT NULL DEFAULT cu.uuid_new(),
	CONSTRAINT chat_pk  PRIMARY KEY (id),
	CONSTRAINT ck_valid CHECK (valid_from < valid_to)
);

CREATE TABLE cu.member (
	id                UUID NOT NULL DEFAULT cu.uuid_new(),
	account_id        UUID NOT NULL,
	chat_id           UUID NOT NULL,
	is_chat_pinned    BOOLEAN NOT NULL DEFAULT FALSE,
	is_chat_muted     BOOLEAN NOT NULL DEFAULT FALSE,
	is_direct_friend  BOOLEAN,
	is_direct_blocked BOOLEAN,
	is_group_owner    BOOLEAN,
	is_group_admin    BOOLEAN,
	valid_from        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	valid_to          TIMESTAMPTZ,
	valid_id          UUID NOT NULL DEFAULT cu.uuid_new(),
	CONSTRAINT member_pk  PRIMARY KEY (id),
	CONSTRAINT fk_account FOREIGN KEY (account_id) REFERENCES cu.account (id),
	CONSTRAINT fk_chat    FOREIGN KEY (chat_id) REFERENCES cu.chat (id)
);

CREATE UNIQUE INDEX member_ux
ON cu.member (account_id, chat_id)
WHERE valid_to IS NULL;

CREATE UNIQUE INDEX member_ux_group_owner
ON cu.member (chat_id, is_group_owner)
WHERE valid_to IS NULL;

CREATE TABLE cu.post (
	id          UUID NOT NULL DEFAULT cu.uuid_new(),
	member_id   UUID,
	reply_to_id UUID,
	message     TEXT,
	valid_from  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	valid_to    TIMESTAMPTZ,
	valid_id    UUID NOT NULL DEFAULT cu.uuid_new(),
	CONSTRAINT post_pk     PRIMARY KEY (id),
	CONSTRAINT fk_member   FOREIGN KEY (member_id) REFERENCES cu.member (id),
	CONSTRAINT fk_reply_to FOREIGN KEY (reply_to_id) REFERENCES cu.post (id)
);

CREATE TABLE cu.receipt (
	id          UUID NOT NULL DEFAULT cu.uuid_new(),
	member_id   UUID NOT NULL,
	post_id     UUID NOT NULL,
	received_at TIMESTAMPTZ,
	viewed_at   TIMESTAMPTZ,
	reactions   TEXT[],
	CONSTRAINT receipt_pk PRIMARY KEY (id),
	CONSTRAINT fk_member  FOREIGN KEY (member_id) REFERENCES cu.member (id),
	CONSTRAINT fk_post    FOREIGN KEY (post_id) REFERENCES cu.post (id),
	CONSTRAINT uq         UNIQUE (member_id, post_id)
);

CREATE TYPE cu.attach_kind AS ENUM (
	'account_picture',
	'chat_picture',
	'post_file'
);

CREATE TABLE IF NOT EXISTS cu.attach (
	id         UUID           NOT NULL DEFAULT cu.uuid_new(),
	kind       cu.attach_kind NOT NULL,
	account_id UUID,
	chat_id    UUID,
	post_id    UUID,
	filename   TEXT NOT NULL,
	content    BYTEA NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	deleted_at TIMESTAMPTZ,
	CONSTRAINT attach_pk  PRIMARY KEY (id),
	CONSTRAINT fk_account FOREIGN KEY (account_id) REFERENCES cu.account (id),
	CONSTRAINT fk_chat    FOREIGN KEY (chat_id) REFERENCES cu.chat (id),
	CONSTRAINT fk_post    FOREIGN KEY (post_id) REFERENCES cu.post (id)
);

CREATE VIEW cu.debug_attach AS
	SELECT
		id,
		kind,
		account_id,
		chat_id,
		post_id,
		filename,
		created_at
	FROM cu.attach
	WHERE attach.deleted_at IS NULL
	ORDER BY created_at DESC;

CREATE UNIQUE INDEX attach_ux_account_picture
ON cu.attach (account_id)
WHERE
	kind = 'account_picture'
	AND deleted_at IS NULL;

CREATE UNIQUE INDEX attach_ux_chat_picture
ON cu.attach (chat_id)
WHERE
	kind = 'chat_picture'
	AND deleted_at IS NULL;

COMMIT;
