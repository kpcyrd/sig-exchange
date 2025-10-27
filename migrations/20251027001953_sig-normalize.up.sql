ALTER TABLE sigs
    DROP COLUMN sig_type,
    DROP COLUMN sig_version,
    DROP COLUMN hash_algo,
    DROP COLUMN sig_algo,
    DROP COLUMN creation_time,
    DROP COLUMN digest_prefix;
