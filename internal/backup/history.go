package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// HistoryStore keeps a readable, diffable history of each device's
// configuration in a local git repository. Every snapshot is one commit; a
// device's file is <device>.cfg holding its config. This gives
// "git log" / "git diff" over time for free.
//
// IMPORTANT: snapshots are stored IN FULL, secrets included — an explicit
// decision (a redacted history can't restore anything, and this store is the
// operator's own audit trail). That makes the rule absolute: this repository
// must never be given a remote, pushed, or copied off the box.
type HistoryStore struct {
	repo *git.Repository
	dir  string
}

// author is the fixed identity for history commits — this is a machine-written
// audit log, not human authorship.
var histAuthor = &object.Signature{Name: "selfsight", Email: "selfsight@localhost"}

// OpenHistory opens the history repo at dir, creating (git init) it on first
// use. The directory is created if missing.
func OpenHistory(dir string) (*HistoryStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	repo, err := git.PlainOpen(dir)
	if err == git.ErrRepositoryNotExists {
		repo, err = git.PlainInit(dir, false)
	}
	if err != nil {
		return nil, fmt.Errorf("history: open %s: %w", dir, err)
	}
	return &HistoryStore{repo: repo, dir: dir}, nil
}

func deviceFile(device string) string { return device + ".cfg" }

// Record commits a device's config as a snapshot taken at when. If the
// content is byte-identical to the current snapshot, nothing is committed and
// ok is false — an unchanged config should not create empty history noise.
func (h *HistoryStore) Record(device string, config []byte, when time.Time, message string) (ok bool, err error) {
	name := deviceFile(device)
	path := filepath.Join(h.dir, name)
	if cur, err := os.ReadFile(path); err == nil && string(cur) == string(config) {
		return false, nil // unchanged — no new commit
	}
	if err := os.WriteFile(path, config, 0o600); err != nil {
		return false, err
	}
	wt, err := h.repo.Worktree()
	if err != nil {
		return false, err
	}
	if _, err := wt.Add(name); err != nil {
		return false, err
	}
	if message == "" {
		message = "snapshot " + device
	}
	sig := *histAuthor
	sig.When = when
	if _, err := wt.Commit(message, &git.CommitOptions{Author: &sig, Committer: &sig}); err != nil {
		return false, err
	}
	return true, nil
}

// Snapshot is one point in a device's config history.
type Snapshot struct {
	Commit  string    `json:"commit"`
	When    time.Time `json:"when"`
	Message string    `json:"message"`
}

// History returns a device's snapshots, newest first.
func (h *HistoryStore) History(device string) ([]Snapshot, error) {
	name := deviceFile(device)
	head, err := h.repo.Head()
	if err == plumbing.ErrReferenceNotFound {
		return []Snapshot{}, nil // empty repo, no history yet
	}
	if err != nil {
		return nil, err
	}
	iter, err := h.repo.Log(&git.LogOptions{From: head.Hash(), FileName: &name})
	if err != nil {
		return nil, err
	}
	var out []Snapshot
	err = iter.ForEach(func(c *object.Commit) error {
		out = append(out, Snapshot{Commit: c.Hash.String(), When: c.Author.When, Message: c.Message})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].When.After(out[j].When) })
	return out, nil
}

// Diff returns the change in a device's config file between two commits (as
// returned by History): a plain-English summary of the changes it understands
// plus the full line diff. An empty fromCommit diffs against the empty tree
// (the whole config as additions).
func (h *HistoryStore) Diff(device, fromCommit, toCommit string) (diff string, summary []string, err error) {
	name := deviceFile(device)
	to, err := h.commitFileContent(toCommit, name)
	if err != nil {
		return "", nil, err
	}
	var from string
	if fromCommit != "" {
		from, err = h.commitFileContent(fromCommit, name)
		if err != nil {
			return "", nil, err
		}
	}
	return unifiedDiff(from, to), Summarize(from, to), nil
}

func (h *HistoryStore) commitFileContent(hash, name string) (string, error) {
	c, err := h.repo.CommitObject(plumbing.NewHash(hash))
	if err != nil {
		return "", err
	}
	f, err := c.File(name)
	if err != nil {
		return "", err
	}
	return f.Contents()
}
