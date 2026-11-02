-- Each block is one hypothesis check. `-- name:` marks a query for pipeline/analyze.py.
-- All queries can also be run by hand:  sqlite3 data/urls.db < sql/hypotheses.sql

-- name: h0_artifact
-- Data quality: how often the URL carries a scheme, per class. A large gap means
-- that any feature touching the scheme reflects the source, not the danger.
SELECT label,
       COUNT(*)                                   AS n,
       ROUND(100.0 * AVG(has_scheme), 1)          AS pct_with_scheme,
       ROUND(AVG(url_length_raw - url_length), 2) AS avg_chars_added_by_scheme
FROM urls
GROUP BY label
ORDER BY label;

-- name: h1_length
-- H1: phishing URLs are longer. Length is measured without the scheme.
WITH ranked AS (
    SELECT label, url_length,
           ROW_NUMBER() OVER (PARTITION BY label ORDER BY url_length) AS rn,
           COUNT(*)     OVER (PARTITION BY label)                     AS n
    FROM urls
)
SELECT label,
       MAX(n)                                                         AS n,
       ROUND(AVG(url_length), 1)                                      AS avg_length,
       AVG(CASE WHEN rn IN ((n + 1) / 2, (n + 2) / 2) THEN url_length END) AS median_length
FROM ranked
GROUP BY label
ORDER BY label;

-- name: h1_length_raw
-- H1 (naive version): the same metric on the raw string, to show the artefact effect.
SELECT label,
       ROUND(AVG(url_length_raw), 1) AS avg_length_raw,
       ROUND(AVG(url_length), 1)     AS avg_length_clean
FROM urls
GROUP BY label
ORDER BY label;

-- name: h1_length_by_scheme
-- H1 robustness: compare classes inside groups that come from similar sources
-- (URLs with a scheme vs. without one).
SELECT has_scheme,
       label,
       COUNT(*)                  AS n,
       ROUND(AVG(url_length), 1) AS avg_length
FROM urls
GROUP BY has_scheme, label
HAVING COUNT(*) >= 1000
ORDER BY has_scheme, label;

-- name: h2_ip
-- H2: an IP address instead of a domain name is more common in malicious URLs.
SELECT label,
       COUNT(*)                            AS n,
       SUM(has_ip)                         AS with_ip,
       ROUND(100.0 * AVG(has_ip), 3)       AS pct_ip
FROM urls
GROUP BY label
ORDER BY label;

-- name: h3_suspicious
-- H3: phishing has more "suspicious" elements: @, dots, subdomains, hyphens.
SELECT label,
       ROUND(100.0 * AVG(count_at > 0), 2)  AS pct_with_at,
       ROUND(AVG(count_dot), 2)             AS avg_dots,
       ROUND(AVG(count_subdomains), 3)      AS avg_subdomains,
       ROUND(AVG(count_hyphen), 2)          AS avg_hyphens,
       ROUND(AVG(host_hyphens), 3)          AS avg_host_hyphens
FROM urls
GROUP BY label
ORDER BY label;

-- name: h4_https
-- H4: https does not guarantee safety. Shares are computed two ways: over all
-- URLs (biased: most benign URLs have no scheme at all) and only over URLs that
-- carry a scheme (the fair comparison).
SELECT label,
       COUNT(*)                                                  AS n,
       SUM(is_https)                                             AS https_urls,
       ROUND(100.0 * AVG(is_https), 2)                           AS pct_https_all,
       SUM(has_scheme)                                           AS urls_with_scheme,
       ROUND(100.0 * SUM(is_https) / NULLIF(SUM(has_scheme), 0), 2) AS pct_https_among_scheme
FROM urls
GROUP BY label
ORDER BY label;

-- name: h4_https_composition
-- H4 from the other side: of all https URLs, what share is malicious?
SELECT label,
       COUNT(*)                                          AS https_urls,
       ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct_of_https_urls
FROM urls
WHERE is_https = 1
GROUP BY label
ORDER BY label;
