package fsm

import (
	"encoding/binary"
	"testing"

	"github.com/canopy-network/canopy/lib"
	"github.com/canopy-network/canopy/store"
)

// BenchmarkIndexerAccountSelection models the staging account cardinality and
// isolates the operation removed from the indexer blob hot path: scanning the
// complete account prefix instead of reading the keys changed by one block.
func BenchmarkIndexerAccountSelection(b *testing.B) {
	const accountCount = 1_300_000
	st, err := store.NewStoreInMemory(lib.NewDefaultLogger())
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()

	var changedKey []byte
	for i := uint64(0); i < accountCount; i++ {
		address := make([]byte, 20)
		binary.BigEndian.PutUint64(address[12:], i)
		key := lib.JoinLenPrefix(accountPrefix, address)
		if err = st.Set(key, []byte{1}); err != nil {
			b.Fatal(err)
		}
		changedKey = key
	}
	sm := &StateMachine{store: st}

	b.Run("full_snapshot", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err = sm.IterateAndAppend(AccountPrefix()); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("one_changed_account", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err = sm.valuesForStateKeys([][]byte{changedKey}, AccountPrefix()); err != nil {
				b.Fatal(err)
			}
		}
	})
}
