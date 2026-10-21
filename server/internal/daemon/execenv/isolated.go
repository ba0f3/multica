package execenv

// IsolatedContainerWorkdir is the process cwd inside Docker/bwrap task workers.
// Cursor trust metadata and OpenCode discovery must use this path, not the
// host-side workdir path the daemon prepared on disk.
const IsolatedContainerWorkdir = "/workspace/repo"
