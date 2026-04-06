// Package downstream — Reed-Solomon FEC encoder and decoder for BullStream.
package downstream

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
)

// Downstream packet flag constants (mirror of proto package constants).
const (
	FlagData    uint8 = 0x01
	FlagParity  uint8 = 0x02
	FlagFIN     uint8 = 0x04
	FlagReset   uint8 = 0x08
	FlagPartial uint8 = 0x10
)

// FECEncoder encodes data shards and produces parity shards using Reed-Solomon.
// It assigns sequential SeqNums across data + parity shards per group and calls
// a SendFunc for each encoded shard.
//
// PARTIAL flush: if a group isn't full after FlushInterval, it is sent with the
// PARTIAL flag. Parity shards for a partial group carry a 1-byte ActualDataShards
// prefix.
type FECEncoder struct {
	rs           reedsolomon.Encoder
	dataShards   int
	parityShards int
	shardSize    int
	flushInterval time.Duration

	mu        sync.Mutex
	group     uint32
	pending   [][]byte  // accumulated data shards
	seqBase   uint32    // SeqNum of the first shard in this group
	globalSeq uint32    // monotonic SeqNum counter

	// SendFunc is called for each outgoing shard.
	// seqNum: the packet SeqNum. flags: FlagData or FlagParity | FlagPartial.
	// payload: the shard bytes (with ActualDataShards prefix for partial parity).
	SendFunc func(seqNum uint32, flags uint8, payload []byte) error

	flushTimer *time.Timer
	stopCh     chan struct{}
}

// NewFECEncoder creates a Reed-Solomon encoder.
// shardSize is the maximum size of each data shard in bytes.
// flushInterval is the maximum time to wait before flushing a partial group.
func NewFECEncoder(dataShards, parityShards, shardSize int, flushInterval time.Duration) (*FECEncoder, error) {
	rs, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("fec encoder: %w", err)
	}
	e := &FECEncoder{
		rs:            rs,
		dataShards:    dataShards,
		parityShards:  parityShards,
		shardSize:     shardSize,
		flushInterval: flushInterval,
		pending:       make([][]byte, 0, dataShards),
		stopCh:        make(chan struct{}),
	}
	return e, nil
}

// Write adds a data payload to the current group. When the group reaches
// dataShards entries it is encoded and flushed immediately.
func (e *FECEncoder) Write(ctx context.Context, data []byte) error {
	// Copy data and pad to shardSize.
	shard := make([]byte, e.shardSize)
	copy(shard, data)

	e.mu.Lock()
	if len(e.pending) == 0 {
		// Starting a new group — arm the flush timer.
		e.seqBase = e.globalSeq
		e.flushTimer = time.AfterFunc(e.flushInterval, func() {
			e.mu.Lock()
			defer e.mu.Unlock()
			if len(e.pending) > 0 {
				if err := e.flush(true); err != nil {
					log.Printf("fec: flush timer error: %v", err)
				}
			}
		})
	}
	e.pending = append(e.pending, shard)
	e.globalSeq++

	if len(e.pending) == e.dataShards {
		e.flushTimer.Stop()
		err := e.flush(false)
		e.mu.Unlock()
		return err
	}
	e.mu.Unlock()
	return nil
}

// flush encodes the current pending group and calls SendFunc for each shard.
// partial=true means the group is incomplete (flush timer fired).
// Must be called with e.mu held.
func (e *FECEncoder) flush(partial bool) error {
	if len(e.pending) == 0 {
		return nil
	}
	actualData := len(e.pending)

	// Build full shard set — nil parity shards are allocated by reedsolomon.
	shards := make([][]byte, e.dataShards+e.parityShards)
	for i := 0; i < e.dataShards; i++ {
		if i < actualData {
			shards[i] = e.pending[i]
		} else {
			// Pad absent data shards with zeros.
			shards[i] = make([]byte, e.shardSize)
		}
	}
	for i := e.dataShards; i < e.dataShards+e.parityShards; i++ {
		shards[i] = make([]byte, e.shardSize)
	}
	if err := e.rs.Encode(shards); err != nil {
		return fmt.Errorf("fec encode: %w", err)
	}

	stride := e.dataShards + e.parityShards
	seq := e.seqBase

	// Send data shards.
	for i := 0; i < actualData; i++ {
		flags := uint8(FlagData)
		if partial {
			flags |= FlagPartial
		}
		if e.SendFunc != nil {
			if err := e.SendFunc(seq, flags, shards[i]); err != nil {
				return err
			}
		}
		seq++
	}
	// Advance seq past any absent data shards.
	seq = e.seqBase + uint32(e.dataShards)

	// Send parity shards.
	for i := 0; i < e.parityShards; i++ {
		flags := uint8(FlagParity)
		payload := shards[e.dataShards+i]
		if partial {
			flags |= FlagPartial
			// Prepend 1-byte ActualDataShards for partial parity.
			p := make([]byte, 1+len(payload))
			p[0] = byte(actualData)
			copy(p[1:], payload)
			payload = p
		}
		if e.SendFunc != nil {
			if err := e.SendFunc(seq, flags, payload); err != nil {
				return err
			}
		}
		seq++
	}

	// Advance global seq to cover the full stride.
	if uint32(stride) > e.globalSeq-e.seqBase {
		e.globalSeq = e.seqBase + uint32(stride)
	}
	e.group++
	e.pending = e.pending[:0]
	return nil
}

// Close flushes any remaining data and stops the flush timer.
func (e *FECEncoder) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.flushTimer != nil {
		e.flushTimer.Stop()
	}
	return e.flush(len(e.pending) < e.dataShards && len(e.pending) > 0)
}

// --------------------------------------------------------------------------

// FECDecoder buffers incoming shards by (group) and reconstructs missing ones.
type FECDecoder struct {
	rs           reedsolomon.Encoder
	dataShards   int
	parityShards int
	shardSize    int

	mu     sync.Mutex
	groups map[uint32]*fecGroup // keyed by group number

	// DeliverFunc is called for each fully reconstructed data shard in order.
	DeliverFunc func(dataIndex int, payload []byte)
}

type fecGroup struct {
	shards        [][]byte
	shardReceived []bool
	actualData    int // 0 means full group (non-partial)
	partial       bool
	received      int
}

// NewFECDecoder creates a Reed-Solomon decoder.
func NewFECDecoder(dataShards, parityShards, shardSize int) (*FECDecoder, error) {
	rs, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("fec decoder: %w", err)
	}
	return &FECDecoder{
		rs:           rs,
		dataShards:   dataShards,
		parityShards: parityShards,
		shardSize:    shardSize,
		groups:       make(map[uint32]*fecGroup),
	}, nil
}

// Receive processes one incoming shard. seqNum is the packet SeqNum; flags
// indicates whether this is a data or parity shard (and whether partial).
// payload is the shard bytes.
func (d *FECDecoder) Receive(seqNum uint32, flags uint8, payload []byte) {
	stride := d.dataShards + d.parityShards
	group := seqNum / uint32(stride)
	pos := int(seqNum % uint32(stride))

	d.mu.Lock()
	defer d.mu.Unlock()

	g, ok := d.groups[group]
	if !ok {
		g = &fecGroup{
			shards:        make([][]byte, stride),
			shardReceived: make([]bool, stride),
			actualData:    d.dataShards,
		}
		d.groups[group] = g
	}
	if g.shardReceived[pos] {
		return // duplicate
	}

	// For partial parity shards, extract ActualDataShards from payload prefix.
	if flags&FlagPartial != 0 && flags&FlagParity != 0 {
		if len(payload) < 1 {
			return
		}
		g.actualData = int(payload[0])
		g.partial = true
		payload = payload[1:]
	}

	// Pad/trim shard to shardSize.
	shard := make([]byte, d.shardSize)
	copy(shard, payload)
	g.shards[pos] = shard
	g.shardReceived[pos] = true
	g.received++

	// Try reconstruction once we have enough shards.
	need := g.actualData
	if need <= 0 {
		need = d.dataShards
	}
	if g.received >= need {
		d.tryReconstruct(group, g)
	}
}

// tryReconstruct attempts Reed-Solomon reconstruction and delivers data shards.
// Must be called with d.mu held.
func (d *FECDecoder) tryReconstruct(groupNum uint32, g *fecGroup) {
	// Check if all data shards are already present.
	allData := true
	actualData := g.actualData
	if actualData <= 0 {
		actualData = d.dataShards
	}
	for i := 0; i < actualData; i++ {
		if !g.shardReceived[i] {
			allData = false
			break
		}
	}
	if !allData {
		// Attempt reconstruction.
		if err := d.rs.ReconstructData(g.shards); err != nil {
			log.Printf("fec: reconstruct group %d: %v", groupNum, err)
			delete(d.groups, groupNum)
			return
		}
	}

	// Deliver data shards.
	if d.DeliverFunc != nil {
		for i := 0; i < actualData; i++ {
			if g.shards[i] != nil {
				d.DeliverFunc(i, g.shards[i])
			}
		}
	}
	delete(d.groups, groupNum)
}

// EvictGroup removes a group from the decoder (called after reorder timeout).
func (d *FECDecoder) EvictGroup(seqNum uint32) {
	stride := uint32(d.dataShards + d.parityShards)
	group := seqNum / stride
	d.mu.Lock()
	delete(d.groups, group)
	d.mu.Unlock()
}
