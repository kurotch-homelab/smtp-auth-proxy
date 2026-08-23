package store

import (
	"fmt"

	"github.com/google/uuid"
)

// NewID returns a UUIDv7 string.
//
// Version 7 embeds a timestamp in its most significant bits, so identifiers
// sort by creation time. That keeps index inserts append-only instead of
// scattering them across the B-tree the way a random UUIDv4 would, and it means
// a queue listing ordered by id is also ordered by arrival.
func NewID() string {
	id, err := uuid.NewV7()
	if err != nil {
		// NewV7 only fails if the system random source does, which is fatal for
		// a process that also has to generate passwords and nonces.
		panic(fmt.Sprintf("store: generating a UUIDv7: %v", err))
	}
	return id.String()
}
