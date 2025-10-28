CREATE TABLE sig_links (
    sig_chksum VARCHAR NOT NULL,
    artifact_chksum VARCHAR NOT NULL,

    os VARCHAR NOT NULL,
    pkg VARCHAR NOT NULL,
    version VARCHAR NOT NULL,
    verified BOOLEAN,

    CONSTRAINT fk_sig
        FOREIGN KEY (sig_chksum)
        REFERENCES sigs(chksum)
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX sig_links_idx_uniq
    ON sig_links (sig_chksum, artifact_chksum, os, pkg, version)
    INCLUDE (verified);
CREATE INDEX sig_links_idx_sig ON sig_links (sig_chksum, artifact_chksum, os) INCLUDE (verified);
CREATE INDEX sig_links_idx_artifact ON sig_links (artifact_chksum, sig_chksum, os) INCLUDE (verified);
