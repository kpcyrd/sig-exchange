ALTER TABLE sigs
    ADD COLUMN hash_algo varchar,
    ADD COLUMN creation_time timestamp with time zone;

CREATE INDEX sigs_creation_time ON sigs (creation_time DESC, chksum);
