CREATE INDEX upstreams_idx_os_name_last_observed_issuer
    ON upstreams (os, name, last_observed DESC)
    INCLUDE (issuer);

CREATE INDEX pkgs_idx_os_name_release_datetime_desc
    ON pkgs (os, name, release_datetime DESC);
