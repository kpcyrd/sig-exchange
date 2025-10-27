ALTER TABLE sigs
    ADD COLUMN sig_type smallint,
    ADD COLUMN sig_version smallint,
    ADD COLUMN hash_algo varchar,
    ADD COLUMN sig_algo varchar,
    ADD COLUMN creation_time timestamp with time zone,
    ADD COLUMN digest_prefix varchar;
