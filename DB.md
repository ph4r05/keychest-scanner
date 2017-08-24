# DB description

DB design description and reasoning, future plans.

## Plans

### TLS Scans

In long term, add new last-scan-caching table for the TLS scans (svc_id, tls_desc_id, tls_param_id).

### IP scans

For now managed as watch target with manual DNS resolution (matches requirements for the scan results).

 - At least one working server is needed to look OK.
 - Does not track individual servers, if one is lost and others work, no error is detected.
 - In some specific setup one server can be scanned multiple times for the same SNI
 (2 different watch_targets, same SNI, different DNS result set with intersection).
 -  - To avoid multi-scans the caching mechanism has to be improved - cache TLS scan by `tls_desc`, `svc_id`

Requirements:
 - For all scanned hosts use service for SNI specification.

#### Alternative: per-ip watch_target

Alternative is to track each detected server as watch_traget with `scan_host` having detected IP.

- In this scenario grouping is needed. Service table is used for the SNI name, grouping.

- Association to the user can hold `ip_scan_record_id`, or the `watch_target` itself as both are user unspecific.


