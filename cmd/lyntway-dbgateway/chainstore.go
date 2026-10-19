package main

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// Where each chain stands, kept between runs.
//
// Without this every restart began every chain again at seq 0, and the
// appended receipts file held several genesis receipts for one chain. A
// verifier walking it sees a discontinuity it cannot tell from deletion —
// the accusation a chain exists to refute.

// chainsPathFor names the position file kept beside a receipts file.
func chainsPathFor(receipts string) string { return besideReceipts(receipts, "-chain.json") }

type chainPosition struct {
	NextSeq uint64 `json:"next_seq"`
	Head    string `json:"head"`
}

type chainsFile struct {
	Chains map[string]chainPosition `json:"chains"`
}

// fileChainStore implements govern.ChainStore over one JSON file.
//
// Read on every load and rewritten on every save. That is one small file
// per receipt, which is nothing beside the network round-trip each receipt
// already represents, and it means the file is right after a crash at any
// point rather than right after a clean exit.
type fileChainStore struct {
	path string
	mu   sync.Mutex
}

func newFileChainStore(path string) *fileChainStore {
	return &fileChainStore{path: path}
}

func (s *fileChainStore) LoadChain(chainID string) (nextSeq uint64, head string, found bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cf, err := s.read()
	if err != nil {
		return 0, "", false, err
	}
	pos, ok := cf.Chains[chainID]
	if !ok {
		return 0, "", false, nil
	}
	return pos.NextSeq, pos.Head, true, nil
}

func (s *fileChainStore) SaveChain(chainID string, nextSeq uint64, head string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cf, err := s.read()
	if err != nil {
		return err
	}
	cf.Chains[chainID] = chainPosition{NextSeq: nextSeq, Head: head}
	body, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, append(body, '\n'), 0o600)
}

// read returns the file's contents, or an empty set when there is no file
// yet. Any other failure is returned: a position file that exists and
// cannot be read must not be silently treated as "no chains", because
// that is exactly the fork this store exists to prevent.
func (s *fileChainStore) read() (chainsFile, error) {
	cf := chainsFile{Chains: map[string]chainPosition{}}
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return cf, nil
	}
	if err != nil {
		return cf, err
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		return cf, err
	}
	if cf.Chains == nil {
		cf.Chains = map[string]chainPosition{}
	}
	return cf, nil
}
