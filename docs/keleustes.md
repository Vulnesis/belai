# Keleustes nodes

Keleustes is the desktop Software Factory. It runs on your own machine and is
the server; nothing signs in to it and it launches no sandboxes. A belai host
joins it once with a token Keleustes mints, then keeps a mutually
authenticated control link open so Keleustes can see and manage it.

## Joining

1. In Keleustes, open **Fleet → Add node**, optionally name the node, and
   choose **Create token**. The token (`kls1.…`) is single use and expires
   after 15 minutes by default. The command line works too:
   `keleustes token new --label build-box`.
2. On the host, inside belai, run `/connect <token>`. On a host without the
   TUI, run `belai connect <token>`.

belai decodes the token and dials the addresses it lists in order. It
trusts only the server key whose SPKI SHA-256 the token carries, so a
machine on the path that answers with any other key is refused before the
token's secret is sent. belai then redeems the token with a certificate
signing request for a fresh Ed25519 key. Keleustes signs a client
certificate from its local CA and returns it with the CA certificate.
Every later connection is mutual TLS 1.3 against that CA, with the server
name `keleustes.node`.

The profile lives in `~/.vulnetix/belai/factory/<server id>/` (or under
`$BELAI_HOME`):

| File | What it holds |
|---|---|
| `profile.json` | server id and name, node id, addresses |
| `node.crt` | the issued client certificate |
| `ca.pem` | the Keleustes CA |
| `cursor` | the last server frame applied, so delivery resumes after a restart |
| `control.json` | the factory's control state as the link last heard it (stopped, A2A blackout, reason) |
| `a2a.cursor` | the highest A2A envelope seq this host received from Keleustes |
| `node.key` | the private key, only when there is no OS keychain (mode 0600); otherwise it is in the keychain under `keleustes-node:<server id>` |

`~/.vulnetix/belai/factory/active` names the profile in use. A host belongs
to one Keleustes server at a time.

## The link

While belai runs, the TUI keeps one gRPC stream (`Link`) open to the
server. A host with no TUI keeps it open with `belai connect serve`. Over
the stream:

- belai sends a hello, then its host advert: hostname, OS and architecture,
  belai version, host id, whether `gh` is signed in, and whether it has a
  terminal.
- belai sends a heartbeat at the interval the server asks for (15 s);
  Keleustes answers each heartbeat with an ack.
- Server frames that must not be lost (prompts, commands, dispatches) carry
  a sequence number. belai acks one only after applying it, and the server
  keeps unacked frames and replays them on the next connection.
- A dropped link reconnects with backoff from 1 s up to 30 s.
- The Welcome frame and every `Control` frame carry the factory's control
  state (see [Factory control](#factory-control)). The link owner records it
  for the host before it acks the frame.

The protocol is defined in `proto/keleustes/node/v1/node.proto` in the
Keleustes repository; the Go code under `internal/factorylink/nodev1` is
generated from it.

Everything Keleustes sends is remote content. It goes through the same
classifier and sanitiser paths as the equivalent content from the cloud
console: prompts arrive as remote prompts, board items as `KindKanban`,
repository memory as `KindRepoMemory`, and agent messages as `KindPeer`.

A process that owns the link without taking work (a TUI, `belai connect
serve`) answers a dispatch or a job as refused through `Jobs.Complete`, so
Keleustes never waits on work nobody will start.

## Sessions

While the host has an active profile that is not revoked, every session
belai mirrors goes to Keleustes instead of the Vulnetix website. The TUI and
the sessions `belai rc` starts do this, and so do fleet workers (kind `worker`),
ACP sessions (kind `acp`, upload only) and headless `-prompt` runs (kind
`headless`, upload only: the website never gets one). The Keleustes profile wins: a
host logged in to Vulnetix and joined to Keleustes mirrors to Keleustes only.
The board, the shared memory and the A2A relay go to Keleustes too (see
[Board](#board)); the TUI starts none of the website's streams. The TUI, fleet workers
and `belai rc` send the host audit streams with `Sessions.Audit` (a
`stream_id`, no session) and resume after `Sessions.AuditHead`. `sync.enabled` still decides whether anything is
mirrored. `/sync status` names the Keleustes server, and
`/connect <token>` and `/disconnect` move the live TUI session's mirror
at once: it ends on the old server and registers on the new one. A
revocation takes effect at the next start.

Any belai process calls the `Sessions` service with the node certificate;
none needs the link lock. Mirroring is the same session sync the website
gets (see [Session sync](session-sync.md)), with only the server changed:

| Website | Keleustes |
|---|---|
| register the session | `Sessions.Upsert` (kind `tui` or `rc`, state `live`, `idle` or `waiting` from the turn and ask lines, title, cwd, repository, branch, provider, model, mode, agent, dispatch id), the open ask as `pending_ask`, what the session `accepts`, `git` facts and cumulative `usage` per provider and model, then an empty `Append` to read the server's next index |
| upload lines by seq | `Sessions.Append`, one `Entry` per JSONL line: `index` is the line number, `role` comes from the line's type (`user`, `assistant`, `tool`, `tool_result`, `a2a`, `shell`, `error`, else `system`), `text` is its content, `at_ms` its timestamp, and `meta_json` holds the type, ids and the line's own meta |
| heartbeat | the last `Upsert` again, with a new `updated_at_ms` |
| end | `Sessions.End` with the end reason (and error text, capped at 500 characters), the session rollup's usage per model, its turns and tool calls |
| inbox long-poll | `Sessions.Inbox`, a stream that resumes after the highest item seq received |
| prompt, answer and command acks | `Sessions.Ack`: accepted is `done` (detail: the transcript entry id, or the new control state), refused is `refused` (detail: the reason) |

Appends are idempotent by index, so a restarted host sends only what the
server lacks. A prompt queued behind a running turn is not acked: Keleustes
keeps it undelivered, so a host that exits before running it gets it again.

Inbox items are remote content and get no exemption. They are mapped to the
website's request types and admitted by the same code:

- **Prompt.** Becomes a web prompt. It is only taken with
  `sync.remote_prompts` on, goes through `CleanPrompt` and the classifier like
  a typed prompt, and waits until the session is idle.
- **Answer.** Becomes a web answer to the open ask named by `question_id`.
  It is only taken with `sync.remote_answers` on. A structured answer names
  one of the open ask's option ids in `decision` (a permission's `allow_once`,
  `deny`, ...; a plan review's choice, with `text` as its notes) or, for a
  clarify or mode-choice ask, webask's answer JSON in `payload_json`; the host
  maps it onto the website's answer shape for the kind of the ask it
  published. An unstructured answer's text is the website's answer JSON,
  `{"kind": "permission", "payload": {"decision": "allow_once"}}`. Either way
  the host checks it against the question that is actually open (webask), so
  a decision the ask did not offer is refused. The published ask holds the
  harness-composed title, the tool name and the option ids, never model text
  beyond a clarify questionnaire, and Keleustes shows it as untrusted text.
- **Command.** Becomes a session control, refused unless the session takes
  controls (`belai rc --web-controls`). Only these names are accepted, and
  any other is refused:

  | Name | Becomes |
  |---|---|
  | `stop` | end the session; a running turn is stopped first |
  | `interrupt` | stop the running turn; the session waits for the next prompt |
  | a control name (`mode`, `model`, `effort`, `guardrails`, `ask`, `caveman`, …) | the control line, such as `/mode plan`, parsed by `sessionctl` |
  | `key <key>` | a control key |
  | `checkout <branch>` | a branch switch |
  | `shell <line…>` | a shell line, only with `--web-shell` |
  | `command <name> [args]` | a custom slash command the host holds |

  `stop` and `interrupt` take no arguments and pass the same gate as any
  other control: a session without `--web-controls` refuses them. A TUI
  session takes no commands from Keleustes.

An item addressed to another session is refused. While the factory is
stopped, a prompt is refused with the reason (so it is not delivered
again); answers and commands still arrive, so a stopped factory can still
stop or interrupt a session.

## Board

The board, the shared repository memory and A2A go through the `Board`
service while the host has an active, unrevoked profile, each through the
same code that serves the website, with only the server changed. Every
process calls it with the node certificate; none needs the link. The TUI
runs all three. A session `belai rc` starts syncs the board (a pull before its
first turn, then the same loop) and relays A2A. A one-shot headless run and a
fleet worker push and pull the board through Keleustes too. Everything the
service returns is remote content, classified exactly like the website's
equivalent: board items reach a model only through `KanbanSearch`
(`KindKanban`), memory notes only through `RepoMemoryRead`
(`KindRepoMemory`), and A2A text only as a classified `KindPeer` attachment.
There is no exemption.

### Kanban

`factorylink.KanbanRemote` is the `kanban.Remote` the website's client is,
so `kanban.Syncer` and the local board file are unchanged
([board format](bkan.md#sync-mapping)):

| belai | Keleustes card |
|---|---|
| pull after the cursor | `KanbanPull` with `since_ms` = the board's cursor; the page's `next_since_ms` becomes the cursor |
| push a batch | `KanbanPush`; each card carries the `version` it was based on |
| `ID`, `Title`, `Body`, `Created`, `Updated`, `Deleted` | `id`, `title`, `body`, `created_at_ms`, `updated_at_ms`, `deleted` |
| `ServerVersion` | `version` |
| `Key` | `key`, the card's display key. The server's value is authoritative: it is taken from every pull and never made up on the host. `KanbanSearch` matches it. |
| `List` | `status`: `backlog` → `backlog`, `in_progress` → `doing`, `review` → `review`, `done` → `done`, `blocked` → `todo`. Pulled, `triage` and `review` read as `review`, `todo` and `backlog` as `backlog` (a blocked item comes back blocked). A `triage` card keeps `triage` while belai leaves it in review. |
| `Labels`, `Priority`, `Assignee`, `Branch`, `PR`, `Remote` | `labels`, `priority` (clamped to -2..3), `assignee`, `branch`, `pr_url`, `repo` |
| everything else (project, directory, host and session, history, claim and lease, routing, the security and CLI result fields) | `meta_json` under the key `belai` |
| `ServerMeta` | the rest of `meta_json`, kept as pulled and sent back on every push |

The server's columns win over the copies in the `belai` part, since the
console edits the columns. A push based on a stale version is refused by
Keleustes with its own copy. That item stays dirty, and the copy rides in
front of the next pull, where the ordinary merge settles it: a newer local
edit keeps its fields, takes the server's version and is pushed again; an
older one gives way.

### Repository memory

`factorylink.MemoryRemote` is the `MemoryReplicator`'s client
([repo memory](a2a.md#repo-memory)). It keeps its marks in
`replica-keleustes-<server id>.json` beside the website's `replica.json`, so
neither cursor is read as the other's.

| belai note | Keleustes note |
|---|---|
| repository scope, key `acme/api` | scope `acme/api` |
| profile scope, key `reviewer` | scope `profile:reviewer` |
| (none) | any other scope, such as `global`: not pulled |
| `NoteID` | `id`. A console note's uuid is not a belai note id: it is stored under a stable `web-` id derived from it, and a change this host makes goes back under the uuid. |
| `Text`, `Tags`, `CreatedAt`, `UpdatedAt` | `text`, `tags`, `created_at_ms`, `updated_at_ms` |
| `DeletedAt` | `deleted` |
| `AgentID` | `author` |

Pulls start after `next_since_ms`, and the server keeps the newest change of
each note. The A2A blackout does not stop memory replication.

### A2A

`factorylink.A2ARelay` is the `a2a.Relay`'s client, so the relay's
de-duplication, age limit, blackout and audit are the website's code
([A2A](a2a.md)). Keleustes names an agent `<nodeId>:<sessionId>`:

- **Out.** An envelope a session on this host sends goes by `A2ASend`, from
  `<this node>:<session>`, with the whole belai envelope in `meta_json` and
  its text parts in `text`. A broadcast has an empty `to`; a direct message
  keeps the addressee's agent id.
- **In.** Each process opens `A2AReceive` for its own session and reopens it
  when the session changes. An envelope from another node is handed to the
  relay with its Agent Card's host set to the sending node, so a reply goes
  back by the Keleustes id unchanged. A message addressed to this host's
  `<node>:<session>` is delivered to the local agent. One from this node is
  skipped (the local bus already carried it). An envelope with no belai part
  becomes a plain message to the agent it names. The highest seq received is
  kept in `a2a.cursor`.
- **Blackout.** `A2ASend` answers `refused: "a2a blackout"`, which stops the
  relay as the website's `blackout: true` does. The relay also reads
  `Board.State` when it starts and every minute, so a process that does not
  own the link learns the blackout too. During it nothing is relayed in
  either direction, and the receive stream is closed.

## Factory control

Keleustes can stop the factory and black out A2A. The state arrives in the
Welcome frame and in every `Control` frame, and `Board.State` reads it. The
link owner (the TUI, `belai connect serve` or `belai rc`) records it in
`<profile>/control.json` and sets the host's A2A blackout file
(`a2a/blackout.json`), so every belai process on the host obeys it:

- **Stopped.** `belai rc` refuses every new dispatch and job with "the
  Keleustes factory is stopped" and the reason. Every session on the host
  refuses remote prompts the same way. Sessions already running keep
  running, and still take `stop` and `interrupt`.
- **A2A blackout.** Every relay on the host stops in both directions.

The daemon logs each change, and the TUI shows it as a system line.

## Remote control

With an active profile, `belai rc` serves Keleustes instead of the website.
It needs no Vulnetix login. The preflight replaces the Vulnetix CLI, login
and website checks with a single **Keleustes** check: the profile, and a
mutual TLS handshake with the node certificate. The sync, guardrails and
directory checks are unchanged. `/rc` and `/rc status` work the same way.

The daemon owns the node link and advertises `remote_control`, the
directories it offers (`trusted_dirs`), the providers it has credentials
for, `max_sessions` (`--max`), and its agent profiles and crews. A TUI that
holds the link hands it over: the daemon claims it through
`<profile>/link.want`, and within about ten seconds the TUI drops to
watching. A TUI started while the daemon runs only watches.

A `Dispatch` of kind `session` becomes the same start request a website
dispatch is. It is checked by the same code: the offered and trusted
directory, the mode (`auto` is the host's default, and `agent`, `plan`,
`goal` and `code` are accepted), the provider and model, the agent profile,
the session cap, and a branch's worktree. It is started by the same
`belai rc-session` child, which checks trust again, admits the prompt, and
mirrors its transcript to Keleustes with `dispatch_id` set. A provider the
dispatch's [vault grant](#vault-grants) holds a key for needs no credentials
on the host.

A `Dispatch` of kind `worker` or `crew` becomes the website's worker or crew
start request: `agent` names the worker profile, and `crew` (or `agent`) the
crew. It is checked by the same code (the offered directory, a profile or
crew this host has, the provider and model, a crew's member models) and
started by `belai agent start` as a website start is. Workers run on the
host's own provider configuration unless the dispatch carries a grant: a
worker takes it (see [Vault grants](#vault-grants)), a crew does not. These are refused: a dispatch past its `deadline_ms`, an id that is
not an identifier, an unknown kind, and any dispatch but `stop` and `pause`
while the factory is stopped.

The frame is acked on the link once it is handled, so a replay never starts
a second session. The outcome goes back through `Jobs.Complete` with
`job_id` set to the dispatch id:

- `ok`, with the new `session_id` (a session) or, in `output_json`,
  `{"report": ...}` (a worker or a crew).
- `refused`, with the reason.
- `failed`, when the child process could not be started.

A failed report is retried a few times.

The advert also lists the dispatch kinds and job kinds this daemon takes
(`dispatch_kinds`, `job_kinds`), whether it clones (`can_clone`), the models
each provider offers, each worker profile's card route (`agent_routes`) and
the forge logins it holds (`forges`: every gh, glab and tea login with the host, account and whether
its status check passed, read every minute; never a token).
Keleustes offers nothing a host does not list.

Beyond `session`, `worker` and `crew`, a dispatch may be `stop` (a session
id), `pause` or `resume` (a worker id), or `crew_control` (a crew run
change). Each runs through the same call the website's request uses. A
start carries the website's extra fields: `dirs`, `workspace`, `effort`,
`git_sync`, `ask`, a worker's per-item `budget`, `fill`, `stay`,
`stay_idle_max_s`, `member_models`, `clone`, and `trigger`, which is cleaned
into the provenance line (`keleustes`, `workflow` or `node`: "Started at the
request of another host through Keleustes"). `tier` is `""` or `fast` (a
budget downgrade naming the model). While the factory is stopped only `stop`
and `pause` are taken. A dispatch's `options` are crew and step settings
(`rc.FactoryOptionKeys`): `tests_post_end` and `tests_on_fail` set the
session's test controls (a value other than `off` needs `--web-controls`, as
the control does), `auto_commit_per_task` may only be `false`, `guardrails`
only `on`, `crew_lease_ms` becomes a worker's claim lease, and
`show_internal_work` and `a2a_show` are the console's display. An unknown key,
or a value that would widen what the host allows, refuses the dispatch. The daemon passes
the accepted settings to the session as `belai rc-session -factory-option
key=value`, once per key.

### Resume, fork, answers, gates and one-off workers

A host lists the optional fields it applies in
`Capabilities.dispatch_features` (`resume`, `fork`, `answers`, `gates`,
`adhoc`, `plan_upload`, `session_actions`, `attachments`); Keleustes sends none to a host
that does not list them. None of them is read from a website request.

- **Resume and fork** (`resume_session`, `fork_entry`, a `session` dispatch
  only). The session must be one this host stored for the dispatch's
  directory's project, and that directory must still be offered; anything
  else is refused with "this host has no such session". The daemon starts a
  new session (`belai rc-session -resume ID [-fork ENTRY]`) whose transcript
  is a copy of the old one up to its last entry, or up to the entry a fork
  names (a user message continues from the entry before it, as `/tree`
  does). The copied conversation is replayed as it was admitted; the
  dispatch's prompt is the new session's first turn and is admitted as
  usual. A resume takes no branch or workspace. Each is audited
  `host.dispatch` with the session it continues (`target`).
- **Answers** (`answers_json`, a `session` dispatch). The `-answers` list
  (`[{"choose","note","skip","match"}]`, at most 64 KiB and 64 entries): the
  daemon admits every note through the host's classifier and posture, as a
  prompt is admitted, and refuses the start with "the answers were refused"
  when one is not admitted. The admitted list goes to the session as a 0600
  file under the daemon's state directory (`-answers`), which the session
  reads and removes; it answers the questions nobody on the web takes. The
  audit holds the list's hash, never a note.
- **Harness gates** (`options`: `finish_review=on`, `lint_loop=on`,
  `checkpoints=on`, `code_mode=off`, `commit_mode=off|ask|auto`, aliases
  `none`, `end`, `per_task`; `rc.GateOptionKeys`). Each only tightens the
  session's settings. A value that would loosen the host's own setting is
  left out and audited `host.dispatch` `option_ignored` with the keys
  (`gate`); a malformed value refuses the dispatch.
- **Plan files** (`plan_upload`). When a plan turn of a Keleustes session
  writes its plan, the session adds a `plan_file` entry to its transcript
  (the file's text, its name, size and SHA-256), and the session's end
  carries the hash (`SessionEnd.plan_sha256`). The text is the model's and
  stays untrusted in Keleustes.
- **One-off workers** (`adhoc`, a `worker` dispatch with no `agent`). The
  daemon checks the spec's shape (tool, list and label names, `publish`
  `none`, `draft_pr` or `agent`), admits the prompt through the host's
  classifier, and starts `belai agent start -prompt=… [-tools=…]
  [-claim=…] [-to=…] [-publish=…] [-read-only]`, which builds and validates
  the profile as `agentprofile.Ephemeral` does for the command line. The
  audit holds the prompt's hash and the tool names, never the prompt.

### Attachments

A Keleustes prompt (`Prompt.attachments`) and a `session` dispatch's first
prompt (`Dispatch.attachments`) may carry files and images (feature
`attachments`). They carry references only: a name, a media type, a SHA-256
and a size. The bytes are read with `Sessions.FetchAttachment`, naming the
inbox item or the dispatch that lists them; Keleustes serves only a hash that
item or dispatch of this node lists, and nothing while the factory is paused
or stopped. Every byte stream must match its listed size and hash.

- **Caps** (both sides; `factorylink.CheckAttachments`): at most 8 per prompt
  or dispatch; `image/png` or `image/jpeg` at most 8 MiB; `text/plain` (UTF-8,
  no NUL byte) at most 64 KiB; 16 MiB in all. Anything else is refused.
- **Admission** is the one a local `@` attachment gets
  ([image-attachments.md](image-attachments.md)): an image through
  `internal/imageguard` alone (decoded, bounded, re-encoded as a fresh PNG;
  never the classifier), a text file through the host's classifier and
  posture, as a prompt is admitted (`rc.AdmitAttachments`). One refusal refuses
  the whole prompt (acked `refused`, with the cleaned reason) or the start;
  refused bytes are never echoed.
- **A dispatch's** attachments are read and admitted by the daemon, and the
  admitted ones go to the session in a 0600 file (`-attachments`) that it reads
  and removes; they ride the first turn only. **A later prompt's** are read by
  the session's link and admitted by the session before its turn.
- `belai rc` sessions take them. A terminal session and a fleet worker refuse a
  prompt that carries any, saying so, rather than drop them; a harness session
  and a pix-assistant session refuse a dispatch that carries any.
- The transcript records a marker per attachment (name, kind, size), never the
  bytes. Each prompt or start is audited `host.dispatch` (`attachments`,
  `prompt_attachments`, or `..._refused`) with each attachment's media type,
  size and hash prefix.

### Console session actions

A session started with `--web-controls` also lists `compact`, `relay`,
`undo`, `rewind`, `commit`, `btw` and `rename` in its accepted controls
(`rc.ActionNames`). Each arrives as a `Command` and runs the host's own code,
never a typed line, and each is audited `host.dispatch` `session_action`
with its outcome. While a turn runs only `rename` applies; the rest are
refused with "stop the running turn first". While the factory is stopped
only `undo` and `rewind` are taken, as they only put files and the
conversation back and run no model.

- `compact [focus]` summarises the conversation with the classifier model,
  admits the summary, and continues from it (a `summary` entry, so a resume
  continues from it too).
- `relay [direction]` drafts a handoff note, admits it and raises a
  `relay_review` ask (`approve`, `edit`, `drop`; the draft rides in
  `PendingAsk.relay_json`). It needs ask on, so a person can answer. Only an
  `approve`, or an `edit` whose text is admitted again, replaces the
  conversation with the note; a new prompt closes the review.
- `undo` restores the files of the last checkpoint, as the TUI's `/undo`
  does. `rewind <id>` is the TUI's `/rewind` with `both`: it restores the
  files of the named checkpoint and returns the conversation to just before
  that checkpoint's prompt (`session.RewindPoint`, the same choice the TUI
  makes). The transcript stays append-only: a `branch` line parented to the
  entry before the prompt, then a `system` line with `meta.kind` `rewind`
  (the command id, checkpoint, entry ids, entries and prompts rewound, file
  counts and safety checkpoint), and the next turn sees only the chain up to
  that point. Keleustes reads each line's `parentId` and shows the lines off
  the chain as rewound. A safety copy names no prompt, so a rewind to it
  restores files only. The audit event carries `itemId` (the Keleustes inbox
  item), `checkpoint`, `conversation`, the file counts and, for a rewound
  conversation, `from`, `to`, `rewound` and `prompts`. File checkpoints
  (docs/checkpoints.md) are kept in such a session. The session publishes its checkpoint list as a `checkpoints`
  transcript entry (ids, times, counts, the prompt's cleaned first line),
  which Keleustes shows as `SessionUpsert.checkpoints`.
- `commit [message]` commits the files the session changed since its last
  commit, with the harness's message when none is given.
- `btw <question>` asks a side question (docs/side-question.md); the answer
  is written to the transcript as a system line and never joins the
  conversation.
- `rename <title>` names the session.

The daemon sends its live workers, crew runs and spend as a `HostStatus`
frame on the link when they change and at least every minute (registry
facts, never a log line). It runs the local scheduler, its audit stream and
memory replication against Keleustes. The website's library sync does not run. The forge relay files a worker's
spooled request with Keleustes (`Forge.File`, the request alone; the bundle
stays on this host), and Keleustes's forge coordinator answers with a `steer`
dispatch, checked field by field (`fleet.CoordSpec`) here and again by the
worker.

## Schedules

In factory mode the host's own schedules (`internal/schedule`) keep firing and
sync with Keleustes through `Board.SchedulePull` and `Board.SchedulePush`, as
they do with the website: definitions are versioned both ways, the run record
(last run, status, next run) is the host's alone, and a push based on an older
version than Keleustes holds is a conflict that keeps the owner's edit. The
owner may add, pause or delete a schedule in Keleustes (Fleet); the host still
checks the profile, the directory and the cron before it fires one, and fires
nothing while the factory is stopped. A factory schedule in Keleustes starts a
worker on the node it names, or on the least busy online node with the profile
and the directory, with a `schedule` trigger.

## Library

Keleustes puts library items on a host with a `library_install` dispatch and
takes a host's copy with `library_backup`. Both name items by reference only
(kind, id, name, version). The daemon fetches each document with
`Library.Fetch`, which Keleustes answers only for a recent dispatch to this
node that names the item, and validates it with the same code a website
install uses: a profile as a profile (Keleustes's agent JSON is converted, a
profile another host backed up arrives as its own markdown), an item through
its kind's adapter behind `sync.<kind>`. A hook or an MCP server reaches a host
only through such an explicit install, and Keleustes asks the owner to confirm
it; `Library.Reconcile` never answers `install` for either. The advert's
`inventory` lists the host's profiles and items by kind, name and hash.

A profile may carry the files the agent was written around (Keleustes
agent files): its document lists their paths and hashes and `LibraryDoc.files`
carries the bytes. The daemon checks every one before the profile is saved
(its hash, bounded UTF-8 text within 256 KiB a file, 32 files and 2 MiB, a path
that keeps inside the profile's own directory, no private key or known
token), then writes them into `~/.vulnetix/belai/profiles/files/<profile id>/`
with `agentfiles.Install`, never into a repository. A Keleustes agent's file
paths become its knowledge paths. The install is audited `host.dispatch`
(`profile_files`) with the count and hash prefixes.

The automatic sync runs in factory mode as a reconcile: every five minutes,
while the factory is not stopped, the daemon sends the hashes of the profiles,
crews and items whose sync switch is on with `Library.Reconcile` (no document)
and reads one verdict per item. Keleustes's automatic sync (on unless its
owner turns it off) queues the `library_backup` for a `push` and the
`library_install` (with overwrite) for an `install` itself and names it in the
verdict's `dispatch_id`; that dispatch arrives and is checked like any other.
Hooks and MCP servers never move this way. A `push` or `install` with no
dispatch asks the owner once an hour (attention `action`, subject `library`);
the owner's `library_backup` or `library_install` then moves the document.
Each pass is a `host.dispatch` fact (`library_reconcile`) with counts only.

A teleport's target fetches the profile and crews the session needs itself:
`belai -teleport <teleport-id>` downloads the bundle saying so
(`TeleportRequest.fetch_needs`), then reads each need it lacks with
`Library.Fetch` naming the teleport id, which Keleustes answers only for the
node the teleport is addressed to, while it is ready or delivered, for a need
it stored with the teleport, and never under the kill switch or the A2A
blackout. Each document is validated exactly as a `library_install` one; a
need already on the host is never overwritten. Each outcome is a
`host.teleport` fact (`need_installed`, `need_present`, `need_missing`,
`need_refused`).

## Library scan and import

A `library_scan` dispatch runs the same scan the website asks for and reports
its findings with `Library.ScanReport`: kind, name, path, hash, harness and
verdict per item, never a document. A `library_import` dispatch names one
item the scan reported (its kind, path and hash, and the scan's dispatch); the
daemon resolves the path through the same checks, re-reads the file, refuses
it when its hash is not the scan's, and uploads the canonical item with
`Library.Backup`, which Keleustes takes only for that import and that hash. A
scan or import never installs anything. `project_prefs` dispatches set an
offered directory's preferences under `--web-project-settings`, as the
website's do.

## Cross-host dispatch

A host can ask Keleustes to run work on another node with the `Fleet`
service: `belai connect nodes` lists the nodes it may address, `belai
connect dispatch -on NODE|any -cwd DIR -prompt TEXT [-wait SECONDS]` files a
request and follows it, and `belai connect prompt NODE:SESSION TEXT` prompts
a session elsewhere. Keleustes decides with its node policy, which is off
by default: a rule queues the request, holds it for the owner's approval, or
denies it, a request a model made (`initiated_by` `agent`) always waits for a
person, every request is rate limited per node and refused while the
factory is stopped, and every outcome is audited with this host as origin.
The target sees an ordinary dispatch with a `node` trigger and no vault
grant, and checks it like any other. A prompt also needs the target
session's `sync.remote_prompts` and is withheld under the A2A blackout.

## Attention

In factory mode there is no Vulnetix login to renew, so the daemon asks the
Keleustes owner for what it can name: when a `github` job finds gh signed
out it files `Board.Attention` with kind `gh_login` and reason
`reauth_needed` (at most once an hour). Kinds (`gh_login`,
`provider_credentials`, `approve`, `action`) and reasons are closed lists
and the subject is an identifier, so no model or tool text reaches a
notification. The owner's decision arrives as a replayable
`AttentionDecided` frame and settles the request once.

## Jobs

Keleustes runs no `gh` and calls no model itself: it sends a `Job` to a node
that can. Only `belai rc` takes jobs; a process that owns the link without
taking work answers each as refused. A job is acked on the link when it is
taken, runs in the background (at most four at once), and is answered
through `Jobs.Complete`: `ok` with `output_json`, `refused` with the reason,
or `failed`. It runs for its `deadline_ms` (at most ten minutes; ninety
seconds when it names none), and one that arrives past it is refused. Every
field of a job is untrusted. Any kind but `github`, `forge`, `model`,
`teleport`, `forge_push`, `library`, `knowledge_search`, `init_draft` and
`review` is refused. The host lists the kinds
it runs in `Capabilities.job_kinds`; Keleustes sends a `forge` job only to a
node that lists it, and for github.com falls back to the `github` job on an
older node. Every job's outcome, a refusal included, is a `host.dispatch`
audit fact (`dispatch: job`, the kind, the status; `reason: kill_switch`
when the factory is stopped; a `forge` job's host and CLI as `forge` and
`tool`; a `review` job's `target`, and when it ran its `pr` and `files`).

### `github`

The payload is `{"args": [...], "stdin": "..." | null}`, and the answer
`{"stdout", "stderr", "exit", "truncated"}`. The host runs `gh` with those
arguments as one argv, with no shell, so nothing is split, expanded or
quoted. It is refused unless `gh` is signed in on the host (the
`gh_authenticated` capability, checked again for the job) and the
arguments pass these checks:

- `args[0]` is one of `api`, `pr`, `issue`, `repo`, `run`, `workflow`,
  `release`, `label`, `search`, `status`, `cache`, `ruleset` and `project`.
  Nothing that reads or changes gh's own credentials or configuration
  (`auth`, `config`, `alias`, `secret`, `ssh-key`, `gpg-key`), runs code or
  a remote shell (`extension`, `codespace`), opens a browser or uploads local
  files (`gist`) is allowed.
- `repo clone`, `repo sync`, `repo fork`, `repo create`, `repo deploy-key`,
  `repo set-default`, `pr checkout`, `release upload`, `release download`,
  `run download` and `run watch` are refused: they run git with arguments
  the job controls, push or upload local files, or wait.
- `--` is refused, since gh passes what follows it to git.
- A flag that reads a local file (`--input`, `--body-file`,
  `--notes-file`, `--template`, `--source`, `--file`, and `-F` under `pr`
  and `issue`) takes only `-`, the job's stdin. A typed field
  (`-F`/`--field` under `api`, `workflow` and `run`) may read `@-` and no
  file.
- No argument names a path on the host: absolute, under `~`, a drive or a
  share, or through `..`. The endpoint of `gh api` is an API path and may
  start with `/`.

`gh` runs in a new empty directory that is removed afterwards, in its own
process group, with the scrubbed environment (only gh's own
`GH_TOKEN`/`GITHUB_TOKEN` kept), no prompts, no pager and no colour. Each of
stdout and stderr is capped at 1 MiB. A non-zero exit is still `ok`, with
`exit` set; a run that cannot start or passes its deadline is `failed`.

### `forge`

The payload is `{"cli": "gh" | "glab" | "tea", "host": "<host[:port]>",
"args": [...], "stdin": "..." | null}` and the answer is the `github` job's
(`internal/forgejob/forge.go`). It is refused unless the host holds a
signed-in login for that CLI and host (the `forges` capability, checked
again for the job). The host is never taken from an argument:

- `gh`: the `github` job's checks above, then `--hostname <host>` forced
  right after `api` (a different `--hostname` is refused); any other
  command runs with `GH_HOST=<host>`, and a `-R`/`--repo` naming another
  host is refused.
- `glab`: `api` only, `--hostname <host>` forced, and only these flags:
  `-X`/`--method` (GET, HEAD, POST, PUT, PATCH, DELETE), `-H`/`--header`
  (no credential header), `-f`/`--raw-field`, `-F`/`--field` (no `@file`;
  `@-` only), `--input -`, `-i`/`--include`, `--paginate`, `--silent`.
- `tea`: `api` only, `-l` forced to the tea login this host holds for the
  host (from `tea login list`; the payload's `-l` is dropped), and only
  `-X`, `-H`, `-f`, `-F` (no `@file`), `-d @-` and `-i`; `-o` is refused.
- glab and tea take exactly one API path: no scheme or host, no `..`
  (escaped or not), no `~`.

The CLI runs as the `github` job's `gh` does: no shell, a new empty
directory, its own process group, the scrubbed environment with any
inherited variable that names a host or repository dropped, no prompts, no
pager, and each output stream capped at 1 MiB.

### `model`

The payload is `{"task": ..., ...}`, optionally with `provider` and `model`.
The host runs one non-interactive call of its own provider plumbing, the way
an avatar request is drawn: the repository's settings and posture, the
model the payload names (else the host's own), and the job's vault grant as
that call's provider keys. Every text in the payload is Keleustes's, so it is
cleaned, capped and admitted through the security classifier before a model
reads it, and reaches the model only as labelled data. Refusal reasons are
harness text; no provider or model output is sent as an error.

| `task` | Payload | Answer |
|---|---|---|
| `draft` | `brief` (or `premise`), `workers`, `labels` | `{"profile": {"name", "display_name", "description", "prompt", "tools", "mode"}, "fields", "crews", "provider", "model"}`, the agent builder's draft (`internal/agentdraft`) |
| `avatar` | `displayName`, `palette` (four `#rrggbb`), `reportStyle`, `focus`, `vocabulary` | `{"svg", "provider", "model"}`, only an image `internal/svgguard` admits |
| `classify` | `text` | `{"admitted": true}`, or `{"admitted": false, "reason"}` when the security classifier refuses it |
| `systemone` | `state` (a string or an object), `questions`: `{key: {"type": "noul" or "choice", "instructions", "options", "descriptions"}}` | `{"answers": {key: {"type", "noul"} or {"type", "choice", "probabilities"}}, "calibrated": false, "provider", "model"}`. The classifier model answers; every answer is checked against its question, and a reply that does not fit fails the job. |

Any other task is refused.

### `teleport`

The payload is `{"task": "teleport_upload", "teleportId", "sessionId",
"toNode"}`: Keleustes asks this host, the origin of a session, to send it to
another node. The host refuses unless the task is `teleport_upload`, the
teleport id, session id and node id have their shapes, the session is in this
host's own session store, and it ran in a directory the daemon offers (the
same rule as the website's `teleport_code` request). It then builds the
session's bundle and uploads it with `Teleport.Upload` under that teleport id,
with the header Keleustes checks: this node, the target node, the session, its
title, the size and the SHA-256. The answer is `{"teleportId", "size", "code",
"lines"}`; an upload Keleustes refuses fails the job with its reason. The
bundle, and how the target uses it, are in
[Teleport](teleport.md#keleustes).

### `library`

The payload is `{"task": "convert", "kind": "agent", "format", "name",
"files": {path: base64}}`: Keleustes asks the host to convert a foreign agent
definition its own converter cannot read (`format` is `hermes`, `claws`,
`nemoclaw` or `mini-swe`). The host checks every path before anything is
written (a clean relative path, at most six segments, no `..`, `.git`, drive,
backslash or control character, and no credential file name), at most 1000
files, 1 MiB each and 8 MiB in all, and a `name` that is an identifier. It
writes the files into a fresh private directory, runs the same importer as
`belai agent import` on it (which reads and never executes), and removes the
directory. The answer is `{"doc", "sha256", "name", "format", "notes":
[{"kind", "field", "text"}], "skills": [{"name", "doc", "sha256"}]}`; a
definition the importer refuses is refused with its reason. Nothing is
installed: Keleustes reviews and imports the answer like any other preview.

### `review`

The payload is a `ReviewJobRequest`: `cwd` (a directory the daemon offers)
or `repo` (`owner/name` of one), `target` (`workdir`, `branch` or `pr`;
default `workdir`), `ref` (the branch, or the pull request number), `base`,
optionally `provider` and `model`, and `force`. The host runs the rubric code
review of `belai review` ([Code review](review.md)) in that directory: the same
read-only review turn, caps, validation against the diff and store, with the
model resolved as a `model` job's is and the job's vault grant as the review
turn's provider keys. It is refused unless the directory is offered and
trusted, the target is one of the three words, a branch ref has
`review.ValidRef`'s shape, a pull request is a number, and `review.enabled` is
on. A working tree takes no `ref` or `base`, a pull request no `base`.

The answer is a `ReviewResult`: the verdict (advisory), the findings (`path`,
`line`, `severity`, `criterion`, `body`, `fix`), the target, the head commit,
the pull request, the files reviewed, skipped and dropped, and whether the diff
was truncated, the verdict incomplete or the review answered from the store.
The daemon checks each finding again before it leaves (the closed severity and
criterion lists, the path alphabet, a line, the caps; any other is dropped and
counted) and narrows a `request_changes` that no `blocker` or `major` finding
backs. The model's reply and the diff never leave. Nothing is posted from the
host, whatever `review.post` says: Keleustes posts the findings with its
`pr_review` output, as data.

## Vault grants

A `Dispatch` or a `Job` may carry a `VaultGrant`: provider keys from the
Keleustes vault for that one piece of work. belai holds a grant in memory
only:

- It is never written to a file, a log, a transcript, an error or an argv.
  Formatting a grant (`String`, `%#v`, JSON) shows its id, providers and
  variable names only, and every value is added to the scrubber
  (`vaultenv`), so it is hidden as `[vault:NAME]` from anything belai
  records should it surface anyway.
- It feeds only the provider resolution of its own session or job
  (`credentials.Resolver.UseGrant`), never the process environment or a
  tool's. A value answers only a secret field of the provider it was granted
  for: the field that reads the variable the grant names, or the provider's
  one secret field. A grant can never set a base URL, an account id, the
  provider choice or any other variable. A resolver holding a grant never
  routes through the AI Firewall, so the key reaches only its provider.
- A dispatched session gets its grant on an inherited pipe: the daemon
  encodes it, starts `belai rc-session` with the read end as descriptor 3
  and `BELAI_KELEUSTES_GRANT_FD=3` (a number, not a secret), writes the grant
  once and closes its end. The child clears the variable, marks itself
  non-dumpable, reads the grant and closes the descriptor. The daemon keeps
  no copy.
- It is dropped at its `expires_at_ms` (a session ends then) and when the
  session or job ends. A grant that has already expired is not used.

- A worker dispatch takes its grant the same way: the daemon passes it to
  `belai agent start` on descriptor 3, which passes it to each worker it
  spawns and keeps none. The worker applies it to its own resolver. Keleustes
  caps its life at the dispatch's `stay_idle_max_s`. A crew start takes no
  grant, because a crew run's supervisor starts members after the grant is
  gone.
- A grant may also carry MCP server credentials (`VaultGrant.mcp`: server,
  key, value). They answer `credentials.Resolver.MCPSecret` for that server and
  key only, so they feed only a server entry whose `cred:` reference binds
  the key; a credential no entry binds is never used. They are concealed and
  dropped like provider keys, and are not re-granted after a Keleustes
  restart.

Windows cannot pass a descriptor this way, so a session dispatch with a
grant is refused there. A worker dispatch with a grant is refused there too.

## Host management

`belai rc` on a joined host reports what is installed and configured on it
(`Host.Report`) and runs the host actions the Keleustes Host view sends
(`Host.Actions`, `Host.Progress`; `internal/hostmgmt`). Two flags set the
host's gate, are recorded in `rc/rc.json`, and no setting or action changes
them:

| Flag | Default | What Keleustes may do |
|---|---|---|
| `--keleustes-manage=off\|read\|config\|provision` | `read` | `off`: nothing. `read`: inventory, probes, preflight, `config_get`, `log_tail`. `config`: also settings keys in `config.RemoteKeys`, project preferences (with `--web-project-settings`), trust, per-repo agents, worktree and session pruning. `provision`: also product installs and sign-in, `belai_upgrade`, `rc_restart`, `repo_clone` |
| `--keleustes-shell` | off | with `provision`, run a confirmed argv (no shell, 60 s, 64 KiB of output) |

The kinds are a closed table and each has its class; an unknown kind, a
class Keleustes stated differently, an unknown parameter or a path outside
the allowed roots (symlinks resolved) is refused. While the factory is
stopped every config, provision and shell action is refused, and so is a
read nobody clicked for. During the A2A blackout `config_set` of `a2a.*` and
`sync.remote_*` is refused. A provision or shell action runs only after a
dry run whose preview the person confirmed (`preview_sha256`); a plan that
changed since is refused as stale. Every state change is a `host.action.*`
audit event with the action's origin. Actions run one at a time, and the
queue in `rc/hostactions/` means a replayed action is answered again and
never run twice. `product_auth` passes `VULNETIX_API_KEY` and
`VULNETIX_ORG_ID` from the action's vault grant to the CLI's environment
only. Steps that need root are handed to a person with the exact command;
belai never runs `sudo`.

## Commands

| Command | What it does |
|---|---|
| `/connect <token>` | join the Keleustes server the token names |
| `/connect status` (or `/connect`) | show the server, node id and link state |
| `/disconnect` | stop the link and delete this host's profile and key |
| `belai connect <token>` | join from a shell |
| `belai connect status` | show the profile and test the link once (exit 1 when not online) |
| `belai connect serve` | keep the link open in the foreground |
| `belai connect leave` | same as `/disconnect` |
| `/fleet nodes` | the same list in the TUI |
| `/fleet start <profile> --on <node\|any> [--cwd DIR]`, `/fleet crew <crew> --on ...` | ask Keleustes to start a worker or crew on another node from the TUI; the request's progress shows as system lines |
| `belai connect nodes` | list the other nodes this host may address (see [Cross-host dispatch](#cross-host-dispatch)) |
| `belai connect dispatch -on NODE\|any ...` | ask Keleustes to run a session, worker or crew on another node |
| `belai connect prompt NODE:SESSION TEXT` | prompt a session on another node |
| `belai rc` | serve Keleustes dispatches and jobs on this host (see [Remote control](#remote-control) and [Jobs](#jobs)) |
| `belai -teleport <session-id> -teleport-to <node-id>` | send a session of this host to another node through Keleustes, and print the teleport id |
| `belai -teleport <teleport-id>` | continue, on this host, a session Keleustes holds a teleport bundle for (see [Teleport](teleport.md#keleustes)) |

To try it by hand: mint a token in Keleustes, run `belai connect <token>`,
then `belai rc` (or `belai rc --detach`) in a trusted project. Dispatch a
session from Keleustes. It appears in Keleustes as it runs, and its
outcome is reported against the dispatch.

## Revocation

Revoking a node in Keleustes (Fleet → ⋯ → Revoke, or `keleustes nodes
revoke <id>`) closes its link at once, and its certificate is refused from
then on. belai records the revocation in `profile.json`, stops
reconnecting, and `/connect status` says so. To rejoin, run `/disconnect`
and redeem a new token. Leaving on the host side does not remove the node
from Keleustes; revoke it there too.
