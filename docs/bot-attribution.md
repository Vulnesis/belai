# Bot attribution trailers

Last Updated: 2026-11-28

Inside a Pix sandbox, what Belai commits carries `Co-authored-by`, `Signed-off-by: vulnesis[bot]` and links to the
session and any vulnerability ids. Both bot identities (`attribution.Bots`) are the GitHub App's bot,
`vulnesis[bot] <176591487+vulnesis[bot]@users.noreply.github.com>`, so GitHub credits the commits to vulnesis[bot]. The package is `internal/attribution`; the rules and the other builders are
in the website's `.repo/bot-attribution.md`. `internal/attribution/testdata/attribution-cases.json` is a copy of the
website's shared cases.

## Rules

- The sandbox Worker writes `~/.pix/attribution` (`PIX_ATTRIBUTION_FILE` overrides the path). Without it Belai is
  not in a Pix sandbox and adds nothing, so a developer's own commits are never signed off by a bot.
- The harness runs git with hooks off (`forge.HardenedGit`), so its commits add the trailers in code:
  `fleet.Workspace.Commit` (session from `Workspace.Session`), the TUI commit workflow ([Commit workflow](commit-workflow.md)) and the remote-control
  auto-commit. A model's own `git commit` gets them from the sandbox's global `commit-msg` hook.
- `Workspace.ensureAttribution` runs in `PublishBranch`. It rebases the branch's own commits (`Base..HEAD`) to add
  trailers a repository's own `core.hooksPath` kept the hook from adding. A failed rewrite is aborted and the
  branch is published as it was.
- A pull request body or comment (`attribution.Markdown`: the duplicate-pull-request close comment, the
  merge-conflict comment) carries the link lines only (`attribution.Links`: Session, Finding,
  Vulnerability, Advisory). `Co-authored-by` and `Signed-off-by` belong to commits alone.
- The worker contract tells the model that trailers are added for it and are not to be written, edited or removed.
- **The committer stays the sandbox's signing identity.** A Keleustes sandbox commits one of two ways
  (website `.repo/pix-sandbox-git-signing.md`):
  - by default the author is `vulnesis[bot] <176591487+vulnesis[bot]@users.noreply.github.com>`, so GitHub
    credits the bot, and the committer is `Vulnesis [bot] <security@vulnes.is>`, signed by the platform key
    so GitHub shows it Verified; any other committer is refused (`not_pix_identity`);
  - when the sandbox owner has a ready signing key in their Secrets Vault, the owner is author and
    committer and their own key signs; any other committer is refused (`not_user_identity`).

  The sandbox sets `GIT_COMMITTER_NAME` and `GIT_COMMITTER_EMAIL` to that committer, which outrank
  `-c user.name` and `-c user.email`, and `proc.ScrubEnvOf` passes them to every command.
  `fleet.identityEnv` never supplies a committer the environment already names (it still supplies an
  author on a machine with no identity). When a Bash command's output holds `not_pix_identity` or
  `not_user_identity`, the harness appends one line: the sandbox signs only as the committer in
  `GIT_COMMITTER_*` (Vulnesis [bot] by default, or the owner with their own key); do not pass
  `-c user.name`/`-c user.email` or `GIT_COMMITTER_*`; set only `GIT_AUTHOR_*` to credit someone else.
- Not covered: `internal/teleport/changes/push.go` commits as `teleport@vulnetix.invalid`, which is not Pix.
