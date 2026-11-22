# Third-party harness sessions

A host joined to Keleustes can run another agent harness (Claude Code, Codex,
pi, opencode, goose, GitHub Copilot CLI, Antigravity CLI and the documented
CLI tier) as a Keleustes session. Belai runs the harness's own interactive
TUI on a pseudo-terminal, types each prompt into it, and mirrors the
harness's own native transcript. Nothing runs the harness in a print or
`exec` mode.

## Detection

`internal/harnessdetect` checks every registry harness with a launch profile
(`tools/gen-harnesses/launch.json`, see [harnesses.md](harnesses.md)):

- the binary is looked up on the daemon's `PATH`, then on the login shell's
  `PATH` (`$SHELL -lc`), and the absolute path is kept;
- `<bin> --version` runs with no shell, a scrubbed environment, a 3 s timeout
  and 4 KiB of output; the first line is sanitized to 64 characters;
- states: `launch` (verified profile, binary answered), `unverified` (the
  profile's facts are not checked; listed, never started), `broken` (probe
  failed), `gui` (a desktop app, open only), `configured` (a config
  directory only, which is never read as installed).

## Running a session

The rc daemon starts `belai rc-harness -dispatch ID -session-id SID -harness
ID [-mode M] [-model M] [-resume NATIVE_ID] [-keys MODE] [-controls]` in the
offered directory. The first prompt is on stdin; a vault grant is on an
inherited descriptor, as for `belai rc-session`.

- The argv comes only from the profile. Every element is a literal or a
  closed placeholder; a model must match `^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`;
  a profile's `never_flags` (skip permissions, yolo, print, exec) can never be
  produced.
- The harness runs as the leader of its own session and process group with
  `TERM=xterm-256color`, belai's scrubbed tool environment and none of
  belai's own variables.
- Per-session files (the A2A bridge config and, for Claude Code, hook
  settings passed with `--settings`) live in `~/.vulnetix/belai/harness/<sid>/`
  (0700) and are removed at the end. The harness's own config is never written.
  The per-session socket the hook and bridge commands dial is in that
  directory, or, when that path is too long for a unix socket, in a fresh
  0700 directory under `XDG_RUNTIME_DIR` (else the temp directory).

### Prompts

A prompt from Keleustes passes `sync.remote_prompts`, `CleanPrompt` and the
kill switch. A prompt that starts with `/`, `!` or `#` is refused: a remote
prompt is never a harness command. Every C0 and C1 control byte except
newline and tab is removed, so a prompt cannot end a bracketed paste early.
The prompt is typed as one bracketed paste and submitted once the harness is
idle, and it is acknowledged only when the harness's own transcript records
it (15 s); otherwise it is refused with "harness did not take the prompt".

### Transcript

`internal/harnesstail` follows the native store read-only, refusing a path
whose real location leaves the store's root: JSONL by byte offset (Claude,
Codex, pi), a rewritten JSON document by message index (Gemini), SQLite
through the read-only `sqlite3` binary (opencode, goose), and aider's
Markdown history. Parsing is `internal/agentstore`'s, shared with
`SearchSessions`. A harness without a readable transcript gets a plain-text
screen snapshot at each turn end. `~/.vulnetix/belai/harness/ledgers/<sid>.jsonl`
maps each mirrored entry to its native offset.

### First-run dialogs

The screen is read through a VT emulator (`charmbracelet/x/vt`) into a cell
grid, so a full-screen TUI that redraws by cursor addressing (Codex) reads as
it looks. The same mechanism maps tool-permission screens: Claude Code's "Do
you want to ..." (1, 2, esc) and Codex's "Would you like to run the following
command?" (y, p, esc) become asks with allow once, allow always and deny.

A profile lists the screens its harness puts up before it takes a prompt
(Claude Code's "Is this a project you created or one you trust?"). When one
is on the screen the session posts an ask with the profile's options (Trust,
Don't trust), Keleustes shows it like any other ask, and no prompt is typed
until it is answered. Only the owner's answer sends keys, and only the fixed
keys the profile names for that option; belai never answers a dialog itself.
Every dialog and answer is audited.

### Questions

When a turn ends and its final reply, read from the native transcript, asks
the owner something (its last paragraph ends with a question mark, or opens
like "Would you like" or "Should I" and holds one), the session posts a
free-text `question` ask. The owner's answer is typed as the next prompt
through the same cleaned, neutralised, kill-switch-checked path, with origin
`owner-answer`; Dismiss closes the ask, and a new prompt supersedes it.

### Usage

The token counts the native transcript records (Claude's `message.usage`,
once per model message; Codex's `token_count`; pi's message usage) become
usage lines that the mirror adds up per provider and model, so Keleustes's
budgets see harness spend. Cost is not in these transcripts and is left to
Keleustes's pricing.

### Resume

`keleustes sessions dispatch --harness <id> --resume <harness_session_id>`,
or Resume on an ended harness session, starts the profile's resume argv
(`claude --resume <uuid>`) in the same directory. The id must have the native
shape and the node must advertise the harness with resume.

### Controls

With `belai rc --web-controls`, `stop` types the exit sequence, then sends
SIGTERM and SIGKILL to the process group; `interrupt` sends the profile's
interrupt key; `key <name>` sends only a key the profile allows. Answers,
shell lines, checkouts and slash commands are refused. When Keleustes stops
the factory every harness session is stopped and new prompts, keys, key
hand-offs and A2A sends are refused.

## Keys

The owner sets the key mode in Keleustes, globally, per harness or per vault
key; the dispatch carries the resolved mode in `-keys`:

| Mode | What reaches the harness |
| --- | --- |
| `own_login` (default) | nothing; the harness uses its own login and any grant is dropped unread |
| `handoff` | the vault key the owner chose for this session |
| `always` | the provider's vault key, for every session of that harness |

A handed-off key is set only in the harness child's environment, only under a
name in the profile's `grant_env` (never a URL, endpoint, proxy or host
variable), and is concealed by the vault scrubber in everything belai records
and mirrors. Belai forgets its copy once the child starts; the session ends
when the grant expires. The harness, its own tools and the same user's
`/proc/<pid>/environ` can read the key, so the mode is an explicit choice.
Every hand-off is audited with the grant id, harness, node, session and mode.

## A2A

When `a2a.enabled` is on and the host's classifier is available, the harness
gets the `belai a2a-mcp --sock PATH` MCP server with the tools `peers`,
`send`, `inbox`, `reply` and `ack`. Received messages are classified
(`KindPeer`) by `internal/a2alink` before the bridge holds them and come back
only as tool results marked `untrusted_peer_message`. When one arrives the
session types a fixed notice line that holds no peer text. The A2A blackout
empties `inbox` and refuses `send`.

`belai harness-hook --sock PATH --event NAME` is the hook command Claude
Code's per-session settings run: it forwards the event and always exits 0
with no output.

## Tests

`internal/harnessrun/testdata/fakeharness` stands in for a harness: it turns
on bracketed paste, reads prompts from its terminal and writes a Claude-shaped
transcript under `$HOME`. Its switches are environment variables the tests
set: `FAKE_RAW` (a file that records every line typed), `FAKE_NOPASTE` (no
bracketed paste), `FAKE_IGNORE_EXIT` (ignore the exit line and SIGTERM, to
test escalation), `FAKE_ENV_FILE` (write the variable names it got) and
`FAKE_ECHO` (print one variable's value, to test the scrubber), `FAKE_TRUST` (put up a folder trust dialog first) and
`FAKE_KEY_ENV` (answer the prompt "show key" with whether that variable is
set, never its value), `FAKE_NO_REPLY` (record the prompt and never answer) and
`FAKE_FORK` (resume into a different session id, to test continuity). A prompt `a2a peers`, `a2a inbox` or
`a2a send <to> <text>` makes it call that tool of the bridge it was given
with `--mcp-config`.

## Hardening

- **Continuity.** A resume is offered only for a profile with a continuity
  method (`session-id-match`). Before launch the recorded native file must
  exist; after it, the native records written by the resumed harness (or
  Claude Code's prompt hook) must name the resumed id. Anything else stops
  the session with the closed reason `continuity_unverified`.
- **Timing.** The runner measures spawn to first output (`startupMs`, also a
  `first output` transcript line), spawn to ready, spawn to first reply and
  wall time. Each startup is appended to `<belai home>/harness/timing.jsonl`,
  and detection advertises the p50 and p95 of the last 50 per harness.
- **Outcome.** A session whose last typed prompt got no final assistant turn
  ends as `adapter_error`; one with no reply and no change in the work tree
  gets an `empty_result` warning. Whether the process group is gone after
  the end is recorded as termination verified or unverified.
- **Capabilities and caveats.** The advert carries kill, asks, named and
  continuity flags and the profile's caveats (`{code, note}`).
- **Config directories.** Transcript and login paths under `~/.claude` and
  `~/.codex` follow `CLAUDE_CONFIG_DIR` and `CODEX_HOME`, and project stores
  are named after the real path of the directory.
- **Answers.** An ask's answer may be `{"decision": "<option>"}`, a plain
  option, or `{"answers": {"<ask id>": "<option>"}}`; anything else is
  refused with the list of valid options.
