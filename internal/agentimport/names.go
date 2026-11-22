package agentimport

// SecretName reports whether a file name is a credential store by its name, by
// the same rule a load applies (such a file is never read). A caller staging
// files for ImportItem uses it to refuse them before anything is written.
func SecretName(name string) bool { return secretName(name) }

// Limits a staged tree keeps, the same ones a load applies.
const (
	MaxFiles      = maxFiles
	MaxFileBytes  = maxFileBytes
	MaxTotalBytes = maxTotalBytes
	MaxDepth      = maxDepth
)
