CREATE TABLE issuers (
    fingerprint VARCHAR PRIMARY KEY,
    family VARCHAR NOT NULL
);

CREATE TABLE sigs (
    chksum VARCHAR PRIMARY KEY,
    family VARCHAR NOT NULL,
    issuer VARCHAR NOT NULL,
    sig_type SMALLINT NOT NULL,
    sig_version SMALLINT NOT NULL,
    hash_algo VARCHAR NOT NULL,
    sig_algo VARCHAR NOT NULL,
    creation_time TIMESTAMPTZ NOT NULL,
    digest_prefix VARCHAR NOT NULL,
    bytes BYTEA NOT NULL,

    CONSTRAINT fk_issuer
        FOREIGN KEY (issuer)
        REFERENCES issuers(fingerprint)
        ON DELETE CASCADE
);
CREATE INDEX sigs_family ON sigs (family);
CREATE INDEX sigs_issuer ON sigs (issuer);
CREATE INDEX sigs_creation_time ON sigs (creation_time);
