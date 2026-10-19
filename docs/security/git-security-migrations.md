# Local Git security migration allocation

The current baseline is `231dedb55287ab6e40fd103634a024e4d9d1baeb`.
Historical migration `900000_r2d_project_sharing` on `d14b6f579587ff94e347657d20a1b6ce735f53c3`
is reserved and was not restored. The current main has no historical R2D ACL
tables. These new migrations are a narrow policy prerequisite for protected Git;
they do not change ordinary project discovery or restore the older ACL stack.

The local implementation reserves **900100–900129**. This allocation is
provisional until an authorized tracker update reconciles it with #12. The user
requires local commits only, so no external allocation/comment was written.

| Range | Objects |
| --- | --- |
| 900100 | Provider registry, identity/key/custody jobs, explicit project grants, repository policy, immutable run contexts/grants, audit events and immutability triggers |
| 900101–900117 | One concurrent index per migration; IDs, owner/provider uniqueness, generation/request uniqueness, lineage and lookup indexes |
| 900118 | Generation-specific project consent and fenced provisioning-worker lease |
| 900119 | Immutable restricted output and durable operation journal tables/triggers |
| 900120–900122 | Separate concurrent journal/output identity and context indexes |
| 900123 | Structured restricted-delivery audit metadata on the R2D security event table |
| 900124 | Source quarantine, restore checkpoint and recursive output-input tables |
| 900125–900127 | Separate concurrent quarantine, checkpoint and output-input indexes |
| 900128 | Witnessed-authority mutation guards on existing authority tables |
| 900129 | Separate execution quarantine kind |

Added state uses `r2d_*` side tables with logical references; authority guards
protect existing tables. No upstream columns, foreign keys or cascading actions
are added. Provider rows default disabled, and
there is no public provider/secret-path administration API. Missing tables deny
protected claim/start rather than selecting an ambient credential path.

Use the normal migration runner outside an explicit transaction. The local
database was migrated through `make migrate-up`; the DB integration suite also
exercises migration application/reversal/reapplication in a disposable schema.
The managed runner applies the current allocation through 900129; see the latest
[review evidence](git-security-local-review.md) for exact frozen checks. Existing ordinary task operation needs the side tables once
this source is installed, because claim/start query the protection registry.

Rollback must pause protected work first. Revert application source and schema
as one coordinated operation; running this application after dropping these
tables fails closed at claim/start. Do not interpret empty restored registry
tables as evidence that previously protected repositories are unprotected.
Witnessed restore quarantine/reconciliation software is implemented. The
independent-domain production restore drill and deployment acceptance remain
operational gates; a local schema round trip alone does not establish them.
