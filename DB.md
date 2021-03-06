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


## Agents

There is one master KeyChest server with primary database copy and the PHP backend. They communicate via Redis interface
(events, jobs) and via API (configuration, changes). PHP parts provides dashboard and management interface (GUI),
sending email alerts, etc...

Architecture supports agents - slave copies of KeyChest scanner.
Agents are installed to private networks so even private services are reachable to the KeyChest scanner. One agent
scans the whole private network. The functionality is very similar to the master node.

Scan results are reported back to the master node which aggregates the results from all agents.
Master node then provides a complete picture to the operator.

Agent -> Master communication is via HTTPS REST API. As Agents are usually installed in the firewalled environment
the communication model is designed so the agent initiates the connection to the master which is supposed to have a public
interface OR there is a SSH tunnel from the agent to the master server. More in `agent.md`.

Master -> Agent eventing is over websocket socket.io protocol.

## Owners

System was refactored so each resource is not attached to the particular user but to the more abstract entity - an owner.

This allows greater flexibility and multi-user setups. By design user can represent more owners. In that case user
sees all resources available to all attached owners. But for the simplicity each user has `primary_owner_id` set -
the primary owner associated to the user. Multiple-owner feature is not fully implemented.

In the current settings two users can share the same view just by setting `primary_owner_id` to the same value.

For individual owners there is 1:1 association to the owner. New owner is created for each newly created user.
It makes the further extensions easier.

Owner can represent a group of users or the whole company. Later, owners could be extended to support hierarchy. This
hierarchical ownership is not implemented yet.

### Authorization

Obviously user can manipulate only resources that belong to the owner user is associated to.

Further operations granularity is implemented by permission system: https://github.com/spatie/laravel-permission
It defines the operations user can do with the resource.

## Monitoring

Monitoring system is designed to be usable by many different entities, the scalability is important requirement.
Users can have overlaps on the monitored services so if two users are monitoring the same service the KeyChest scanner
scans the destination only once. There is an association monitored target <-> user.

## Managed services

Management part of the KeyChest is an executive part - in contrast with pure monitoring part of the original system.
It allows to actively prevent certificate expiration by automated renewal of the certificates before they expire.

Managed services also contain some monitoring part but it differs from the original monitoring KeyChest subsystem.

 - Typically no resource sharing. One monitored target has one owner.
 - More advanced checks supported: physical file check, API support (GET /certificates/)

Abusing the original scanner part for this advanced monitoring and renewal would increase the complexity of the
original scanner part and increase the coupling. As monitoring and management differ quite a lot we decided to
split data model of those two by design to reduce the coupling and checker system complexity which has slightly
different goals and objectives.

All managed models are unique per owner.

DbManagedSolution is the main wrapping model of the managed object. It is e.g., "web", "internetbanking".

DbManagedService is associated to the solution and defined one particular implementation of the solution.
It contains various parameters and settings for this particular solution instance.

DbManagedHost is basic KeyChest monitored host. It represents single VirtualHost instance KeyChest has access to
for monitoring and management. Typically there is DbSshKey associated to the host or API key for the certificate-agent
deployed on the host.

DbHostGroup groups DbManagedHost in a flat hierarchy (i.e., DbHostGroup are not related one to another).
- DbHostGroup and DbManagedHost is many-to-many relation via DbHostToGroupAssoc.
- DbHostGroup can be used in a way Ansible uses groups
- DbHostGroup recommended naming convention: use dot separated names. E.g., webservers.atlanta, production.atlanta.
- DbHostGroup is associated to the DbManagedService via many-to-many relation DbManagedServiceToGroupAssoc.
- Host is not associated with any other managed object on its own. All bindings to services and solution must be
performed via groups as it is easier to extend and manage after system grows.
- Each added host should have assigned so-called single-host DbHostGroup to overcome limitation of the previous point.

DbManagedService + DbManagedTestProfile define the certificate check and renewal parameters, policies, etc...,
for all associated hosts (associated via host groups).
There is no direct host parameter association as we want to avoid such relations.

DbManagedTest keeps track of the KeyChest certificate checks on particular hosts for given (solution, service) tuple.
It tracks (solution, service, host) -> {last_scan_at, ...}. Managed certificate checks are scheduled based on
this relation. Test can be also passive - result pushed from the ManagedHost by the certificate-agent.

DbManagedCertificate associates (solution, service) tuple to the active certificate set. The certificate set is
watched for the whole service and should be present on all hosts associated to the service.
 - Model supports retrieval of all active certs for the given service easily (record_deprecated_at == None)
 - In majority of cases there will be just one active certificate (with record_deprecated_at == None) associated.
 - The model also supports scenarios with dual certificates (RSA + ECC).
 - The model keeps track of a check and renewal process for particular certificates.
 - Active certificates are supposed to be deployed to associated hosts (via service).
 - Contains renewal history chain.

DbManagedCertIssue keeps track of certificate renewal process in more detail - some kind of logging.

DbManagedCertificate sync options:
 - Manual entry
 - watch target sync
 - crt.sh sync
 - host check sync

DbManagedCertificate can be created also by the test object:  If the active certificate set is empty
the DbManagedTest s can create an active certificate set.
- Certificate uniqueness can be determined by subject & issuer comparison (+ extensions). The meaning
of the test is to detect renewed certificates and phase them out.

### Design use-cases, goals, objectives

- Consider multiple different certificates for one (solution, service, host). E.g., RSA, ECC certs.
We may want to renew all, can have different validity and policy. Each certificate defined by a separate service.

- Dual certificates (ECC+RSA) could have requirement that the renewal process has to be synchronous for both.
Such certificates could not be treated independently as individual renewal would not work. Dual certificates should
be configured in the service itself. *Extension*: Certificate profiles

- Consider more different monitoring strategies:
  - Standard TLS check
  - More protocols check (START-TLS, another protocols)
  - Physical file check (ansible)
  - API call
  - Passive check - submitted by the installed endpoint certificate-agent.

- All cert properties, configuration, renewal policies and mechanisms should be the same in the
managed service -> delegates to associated hosts via groups.

- One cert can be shared across multiple hosts.
  - Monitoring - monitor all hosts if they have valid certs.
  - Renewal - renew only once (e.g., LetsEncrypt, Vault), then sync on the end hosts.

