CREATE TABLE artifacts (
    chksum VARCHAR NOT NULL,
    url VARCHAR NOT NULL,
    os VARCHAR NOT NULL,
    pkg VARCHAR NOT NULL,
    version VARCHAR NOT NULL
);

CREATE UNIQUE INDEX artifacts_idx_uniq ON artifacts (chksum, url, os, pkg, version);
