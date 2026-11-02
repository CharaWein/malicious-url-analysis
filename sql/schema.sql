CREATE TABLE urls (
    id                  INTEGER PRIMARY KEY,
    url                 TEXT    NOT NULL UNIQUE,
    label               TEXT    NOT NULL CHECK (label IN ('benign', 'defacement', 'malware', 'phishing')),
    split               TEXT    NOT NULL,
    is_malicious        INTEGER NOT NULL,
    has_scheme          INTEGER NOT NULL,   -- URL starts with "<scheme>://"
    is_https            INTEGER NOT NULL,
    url_length_raw      INTEGER NOT NULL,   -- length as stored in the source
    url_length          INTEGER NOT NULL,   -- length without scheme (artefact-free)
    host                TEXT    NOT NULL,
    host_length         INTEGER NOT NULL,
    path_length         INTEGER NOT NULL,
    has_ip              INTEGER NOT NULL,
    has_port            INTEGER NOT NULL,
    count_at            INTEGER NOT NULL,
    count_dot           INTEGER NOT NULL,
    count_hyphen        INTEGER NOT NULL,
    host_hyphens        INTEGER NOT NULL,
    count_digits        INTEGER NOT NULL,
    count_query_params  INTEGER NOT NULL,
    count_subdomains    INTEGER NOT NULL
);

CREATE INDEX idx_urls_label ON urls (label);
