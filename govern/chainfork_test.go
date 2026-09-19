package govern

import (
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// lockingChainStore is a shared store that serialises placement, as the
// Postgres one does with a row lock.
type lockingChainStore struct {
	mu    sync.Mutex
	heads map[string][2]any
	fail  error
}

func (m *lockingChainStore) LoadChain(id string) (uint64, string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.heads[id]
	if !ok {
		return 0, "", false, nil
	}
	return h[0].(uint64), h[1].(string), true, nil
}

func (m *lockingChainStore) SaveChain(string, uint64, string) error {
	panic("an engine with a locking store must not fall back to last-writer-wins")
}

func (m *lockingChainStore) LockChain(id string, place func(uint64, string, bool) (uint64, string, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.heads == nil {
		m.heads = map[string][2]any{}
	}
	var seq uint64
	var head string
	h, found := m.heads[id]
	if found {
		seq, head = h[0].(uint64), h[1].(string)
	}
	next, nextHead, err := place(seq, head, found)
	if err != nil {
		return err
	}
	if m.fail != nil {
		return m.fail
	}
	m.heads[id] = [2]any{next, nextHead}
	return nil
}

// Several replicas writing one chain at once must still produce one chain:
// every sequence number once, each naming the receipt before it.
func TestReplicasCannotForkAChain(t *testing.T) {
	store := &lockingChainStore{}
	signer, err := receipt.GenerateEd25519Signer("test-key-1")
	if err != nil {
		t.Fatal(err)
	}
	var engines []*Engine
	for i := 0; i < 4; i++ {
		e, err := New(Config{Signer: signer, ChainStore: store})
		if err != nil {
			t.Fatal(err)
		}
		engines = append(engines, e)
	}

	var mu sync.Mutex
	var issued []*receipt.Receipt
	var wg sync.WaitGroup
	for i, e := range engines {
		for j := 0; j < 25; j++ {
			wg.Add(1)
			go func(e *Engine, n int) {
				defer wg.Done()
				res, err := e.Govern(req(fmt.Sprintf("rcpt_%d", n), "hello", testScope(t)))
				if err != nil {
					t.Errorf("govern: %v", err)
					return
				}
				mu.Lock()
				issued = append(issued, res.Receipt)
				mu.Unlock()
			}(e, i*100+j)
		}
	}
	wg.Wait()

	sort.Slice(issued, func(a, b int) bool { return issued[a].Chain.Seq < issued[b].Chain.Seq })
	for i, r := range issued {
		if r.Chain.Seq != uint64(i) {
			t.Fatalf("position %d holds seq %d: the chain forked or has a gap", i, r.Chain.Seq)
		}
	}
	keys := receipt.StaticKeyResolver{signer.KeyID(): signer.Public()}
	if _, err := receipt.VerifyChain(issued, keys, receipt.VerifyOptions{}); err != nil {
		t.Fatalf("the chain written by four replicas does not verify: %v", err)
	}
}

// A position that could not be stored withdraws the receipt: the next one
// might take the same sequence number.
func TestAnUnrecordedPositionIssuesNothing(t *testing.T) {
	store := &lockingChainStore{fail: fmt.Errorf("database went away")}
	signer, _ := receipt.GenerateEd25519Signer("test-key-1")
	e, err := New(Config{Signer: signer, ChainStore: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Govern(req("rcpt_x", "hello", testScope(t))); err == nil {
		t.Fatal("a receipt was issued whose chain position was never recorded")
	}
	store.fail = nil
	res, err := e.Govern(req("rcpt_y", "hello", testScope(t)))
	if err != nil || res.Receipt.Chain.Seq != 0 {
		t.Fatalf("after recovery: %v, seq %d; want the chain to start at 0", err, res.Receipt.Chain.Seq)
	}
}
