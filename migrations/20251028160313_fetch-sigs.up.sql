CREATE TABLE remote_sigs (
    url VARCHAR NOT NULL,
    family VARCHAR NOT NULL,
    next_fetch TIMESTAMPTZ NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    sigs VARCHAR[],
    artifact_chksums VARCHAR[] NOT NULL,
    os VARCHAR NOT NULL,
    pkg VARCHAR NOT NULL,
    version VARCHAR NOT NULL
);

CREATE INDEX remote_sigs_idx_queue
    ON remote_sigs (next_fetch)
    WHERE sigs IS NULL;
CREATE UNIQUE INDEX remote_sigs_idx_uniq ON remote_sigs (url, family, os, pkg, version);
