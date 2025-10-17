CREATE TABLE pkgs (
    os VARCHAR NOT NULL,
    name VARCHAR NOT NULL,
    version VARCHAR NOT NULL,
    release_datetime TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX pkgs_idx_uniq ON pkgs (os, name, version);
CREATE INDEX pkgs_idx_os ON pkgs (os);
CREATE INDEX pkgs_idx_name ON pkgs (name);
CREATE INDEX pkgs_idx_release_datetime ON pkgs (os, name, release_datetime);

CREATE TABLE upstreams (
    os VARCHAR NOT NULL,
    name VARCHAR NOT NULL,
    issuer VARCHAR NOT NULL,
    last_observed TIMESTAMPTZ NOT NULL,

    CONSTRAINT fk_issuer
        FOREIGN KEY (issuer)
        REFERENCES issuers(fingerprint)
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX upstreams_idx_uniq ON upstreams (os, name, issuer);
CREATE INDEX upstreams_idx_os ON upstreams (os);
CREATE INDEX upstreams_idx_name ON upstreams (name);
CREATE INDEX upstreams_idx_issuer ON upstreams (issuer);
