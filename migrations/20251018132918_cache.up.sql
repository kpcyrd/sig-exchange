CREATE TABLE cache (
    url VARCHAR PRIMARY KEY,
    filename VARCHAR,
    content BYTEA NOT NULL
);
CREATE INDEX idx_cache_filename ON cache(filename);
