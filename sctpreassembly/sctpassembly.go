package sctpreassembly

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
)

// TODO:
// - push to Stream on Ack
// - implement chunked (cheap) reads and Reader() interface
// - better organize file: split files: 'mem', 'misc' (seq + flow)

var defaultDebug = false

var debugLog = flag.Bool("sctp_assembly_debug_log", defaultDebug, "If true, the github.com/kubeshark/gopacket/sctpreassembly library will log verbose debugging information (at least one line per packet)")

const initialTSN = 0
const uint32Max = 0xFFFFFFFF

// Sequence is a SCTP sequence number.  It provides a few convenience functions
// for handling SCTP wrap-around.  The sequence should always be in the range
// [0,0xFFFFFFFF]... its other bits are simply used in wrap-around calculations
// and should never be set.
type Sequence uint32

// Difference defines an ordering for comparing SCTP sequences that's safe for
// roll-overs.  It returns:
//
//	> 0 : if t comes after s
//	< 0 : if t comes before s
//	  0 : if t == s
//
// The number returned is the sequence difference, so 4.Difference(8) will
// return 4.
//
// It handles rollovers by considering any sequence in the first quarter of the
// uint32 space to be after any sequence in the last quarter of that space, thus
// wrapping the uint32 space.
func (s Sequence) Difference(t Sequence) int {
	if s > uint32Max-uint32Max/4 && t < uint32Max/4 {
		t += uint32Max
	} else if t > uint32Max-uint32Max/4 && s < uint32Max/4 {
		s += uint32Max
	}
	return int(t - s)
}

// Add adds an integer to a sequence and returns the resulting sequence.
func (s Sequence) Add(t int) Sequence {
	return (s + Sequence(t)) & uint32Max
}

// SCTPAssemblyStats provides some figures for a ScatterGather
type SCTPAssemblyStats struct {
	// For this ScatterGather
	Chunks  int
	Packets int
	// For the half connection, since last call to ReassembledSG()
	QueuedBytes    int
	QueuedPackets  int
	OverlapBytes   int
	OverlapPackets int
}

// ScatterGather is used to pass reassembled data and metadata of reassembled
// packets to a Stream via ReassembledSG
type ScatterGather interface {
	// Returns the length of available bytes and saved bytes
	Lengths() (int, int)
	// Returns the bytes up to length (shall be <= available bytes)
	Fetch(length int) []byte
	// Tell to keep from offset
	KeepFrom(offset int)
	// Return CaptureInfo of packet corresponding to given offset
	CaptureInfo(offset int) gopacket.CaptureInfo
	// Return some info about the reassembled chunks
	Info() (direction SCTPFlowDirection, start bool, end bool)
	// Return some stats regarding the state of the stream
	Stats() SCTPAssemblyStats
}

// byteContainer is either a page or a livePacket
type byteContainer interface {
	getBytes() []byte
	length() int
	convertToPages(*pageCache, int, AssemblerContext) (*page, *page, int)
	captureInfo() gopacket.CaptureInfo
	assemblerContext() AssemblerContext
	release(*pageCache) int
	isStart() bool
	isEnd() bool
	getSeq() Sequence
	isPacket() bool
}

// Implements a ScatterGather
type reassemblyObject struct {
	all       []byteContainer
	Direction SCTPFlowDirection
	saved     int
	toKeep    int
	// stats
	queuedBytes    int
	queuedPackets  int
	overlapBytes   int
	overlapPackets int
}

func (rl *reassemblyObject) Lengths() (int, int) {
	l := 0
	for _, r := range rl.all {
		l += r.length()
	}
	return l, rl.saved
}

func (rl *reassemblyObject) Fetch(l int) []byte {
	if l <= rl.all[0].length() {
		return rl.all[0].getBytes()[:l]
	}
	bytes := make([]byte, 0, l)
	for _, bc := range rl.all {
		bytes = append(bytes, bc.getBytes()...)
	}
	return bytes[:l]
}

func (rl *reassemblyObject) KeepFrom(offset int) {
	rl.toKeep = offset
}

func (rl *reassemblyObject) CaptureInfo(offset int) gopacket.CaptureInfo {
	if offset < 0 {
		return gopacket.CaptureInfo{}
	}

	current := 0
	for _, r := range rl.all {
		if current+r.length() > offset {
			return r.captureInfo()
		}
		current += r.length()
	}
	// Invalid offset
	return gopacket.CaptureInfo{}
}

func (rl *reassemblyObject) Info() (SCTPFlowDirection, bool, bool) {
	return rl.Direction, rl.all[0].isStart(), rl.all[len(rl.all)-1].isEnd()
}

func (rl *reassemblyObject) Stats() SCTPAssemblyStats {
	packets := int(0)
	for _, r := range rl.all {
		if r.isPacket() {
			packets++
		}
	}
	return SCTPAssemblyStats{
		Chunks:         len(rl.all),
		Packets:        packets,
		QueuedBytes:    rl.queuedBytes,
		QueuedPackets:  rl.queuedPackets,
		OverlapBytes:   rl.overlapBytes,
		OverlapPackets: rl.overlapPackets,
	}
}

const pageBytes = 1900

// SCTPFlowDirection distinguish the two half-connections directions.
//
// SCTPDirClientToServer is assigned to half-connection for the first received
// packet, hence might be wrong if packets are not received in order.
// It's up to the caller (e.g. in Accept()) to decide if the direction should
// be interpretted differently.
type SCTPFlowDirection bool

// Value are not really useful
const (
	SCTPDirClientToServer SCTPFlowDirection = false
	SCTPDirServerToClient SCTPFlowDirection = true
)

func (dir SCTPFlowDirection) String() string {
	switch dir {
	case SCTPDirClientToServer:
		return "client->server"
	case SCTPDirServerToClient:
		return "server->client"
	}
	return ""
}

// Reverse returns the reversed direction
func (dir SCTPFlowDirection) Reverse() SCTPFlowDirection {
	return !dir
}

/* page: implements a byteContainer */

// page is used to store SCTP data we're not ready for yet (out-of-order
// packets).  Unused pages are stored in and returned from a pageCache, which
// avoids memory allocation.  Used pages are stored in a doubly-linked list in
// a connection.
type page struct {
	bytes      []byte
	seq        Sequence
	prev, next *page
	buf        [pageBytes]byte
	ac         AssemblerContext // only set for the first page of a packet
	seen       time.Time
	start, end bool
}

func (p *page) getBytes() []byte {
	return p.bytes
}
func (p *page) captureInfo() gopacket.CaptureInfo {
	return p.ac.GetCaptureInfo()
}
func (p *page) assemblerContext() AssemblerContext {
	return p.ac
}
func (p *page) convertToPages(pc *pageCache, skip int, ac AssemblerContext) (*page, *page, int) {
	if skip != 0 {
		p.bytes = p.bytes[skip:]
		p.seq = p.seq.Add(skip)
	}
	p.prev, p.next = nil, nil
	return p, p, 1
}
func (p *page) length() int {
	return len(p.bytes)
}
func (p *page) release(pc *pageCache) int {
	pc.replace(p)
	return 1
}
func (p *page) isStart() bool {
	return p.start
}
func (p *page) isEnd() bool {
	return p.end
}
func (p *page) getSeq() Sequence {
	return p.seq
}
func (p *page) isPacket() bool {
	return p.ac != nil
}
func (p *page) String() string {
	return fmt.Sprintf("page@%p{seq: %v, bytes:%d, -> nextSeq:%v} (prev:%p, next:%p)", p, p.seq, len(p.bytes), p.seq+Sequence(len(p.bytes)), p.prev, p.next)
}

/* livePacket: implements a byteContainer */
type livePacket struct {
	bytes []byte
	start bool
	end   bool
	ac    AssemblerContext
	seq   Sequence
}

func (lp *livePacket) getBytes() []byte {
	return lp.bytes
}
func (lp *livePacket) captureInfo() gopacket.CaptureInfo {
	return lp.ac.GetCaptureInfo()
}
func (lp *livePacket) assemblerContext() AssemblerContext {
	return lp.ac
}
func (lp *livePacket) length() int {
	return len(lp.bytes)
}
func (lp *livePacket) isStart() bool {
	return lp.start
}
func (lp *livePacket) isEnd() bool {
	return lp.end
}
func (lp *livePacket) getSeq() Sequence {
	return lp.seq
}
func (lp *livePacket) isPacket() bool {
	return true
}

// Creates a page (or set of pages) from a SCTP packet: returns the first and last
// page in its doubly-linked list of new pages.
func (lp *livePacket) convertToPages(pc *pageCache, skip int, ac AssemblerContext) (*page, *page, int) {
	ts := lp.captureInfo().Timestamp
	first := pc.next(ts)
	current := first
	current.prev = nil
	first.ac = ac
	numPages := 1
	seq, bytes := lp.seq.Add(skip), lp.bytes[skip:]
	for {
		length := min(len(bytes), pageBytes)
		current.bytes = current.buf[:length]
		copy(current.bytes, bytes)
		current.seq = seq
		bytes = bytes[length:]
		if len(bytes) == 0 {
			current.end = lp.isEnd()
			current.next = nil
			break
		}
		seq = seq.Add(length)
		current.next = pc.next(ts)
		current.next.prev = current
		current = current.next
		current.ac = nil
		numPages++
	}
	return first, current, numPages
}
func (lp *livePacket) estimateNumberOfPages() int {
	return (len(lp.bytes) + pageBytes + 1) / pageBytes
}

func (lp *livePacket) release(*pageCache) int {
	return 0
}

// Stream is implemented by the caller to handle incoming reassembled
// SCTP data.  Callers create a StreamFactory, then StreamPool uses
// it to create a new Stream for every SCTP stream.
//
// assembly will, in order:
//  1. Create the stream via StreamFactory.New
//  2. Call ReassembledSG 0 or more times, passing in reassembled SCTP data in order
//  3. Call ReassemblyComplete one time, after which the stream is dereferenced by assembly.
type Stream interface {
	// Tell whether the SCTP packet should be accepted, start could be modified to force a start even if no SYN have been seen
	Accept(sctp *layers.SCTP, ci gopacket.CaptureInfo, dir SCTPFlowDirection, nextSeq Sequence, start *bool, ac AssemblerContext) bool

	// ReassembledSG is called zero or more times.
	// ScatterGather is reused after each Reassembled call,
	// so it's important to copy anything you need out of it,
	// especially bytes (or use KeepFrom())
	ReassembledSG(sg ScatterGather, ac AssemblerContext)

	// ReassemblyComplete is called when assembly decides there is
	// no more data for this Stream, either because a FIN or RST packet
	// was seen, or because the stream has timed out without any new
	// packet data (due to a call to FlushCloseOlderThan).
	// It should return true if the connection should be removed from the pool
	// It can return false if it want to see subsequent packets with Accept(), e.g. to
	// see FIN-ACK, for deeper state-machine analysis.
	ReassemblyComplete(ac AssemblerContext) bool

	// ReceivePacket is called by AssembleWithContext when the belonging of the packet
	// to which SCTP stream is determined and after the Accept call returns true.
	// Its purpose is to recollect the packets into their corresponding SCTP reassembly streams.
	// The caller can simply define an empty implementation or append to a []gopacket.Packet
	// pipe the packet into a some other procedure.
	ReceivePacket(packet gopacket.Packet, sctp *layers.SCTP, dir SCTPFlowDirection)
}

// StreamFactory is used by assembly to create a new stream for each
// new SCTP session.
type StreamFactory interface {
	// New should return a new stream for the given SCTP key.
	New(netFlow, sctpFlow gopacket.Flow, sctp *layers.SCTP, ac AssemblerContext) Stream
}

type key [4]gopacket.Flow

func (k *key) String() string {
	return fmt.Sprintf("%s:%s@%s|%s", k[0], k[1], k[2], k[3])
}

func (k *key) Reverse() key {
	return key{
		k[0].Reverse(),
		k[1].Reverse(),
		k[2].Reverse(),
		k[3].Reverse(),
	}
}

const assemblerReturnValueInitialSize = 16

/* one-way connection, i.e. halfconnection */
type halfconnection struct {
	dir               SCTPFlowDirection
	pages             int   // Number of pages used (both in first/last and saved)
	saved             *page // Doubly-linked list of in-order pages (seq < nextSeq) already given to Stream who told us to keep
	first, last       *page // Doubly-linked list of out-of-order pages (seq > nextSeq)
	currentTSN        Sequence
	created, lastSeen time.Time
	stream            Stream
	closed            bool
	// for stats
	queuedBytes    int
	queuedPackets  int
	overlapBytes   int
	overlapPackets int
}

func (half *halfconnection) String() string {
	closed := ""
	if half.closed {
		closed = "closed "
	}
	return fmt.Sprintf("%screated:%v, last:%v", closed, half.created, half.lastSeen)
}

// Dump returns a string (crypticly) describing the halfconnction
func (half *halfconnection) Dump() string {
	s := fmt.Sprintf("pages: %d\n"+
		"current TSN: %d\n"+
		"Seen :  %s\n"+
		"dir:    %s\n", half.pages, half.currentTSN, half.lastSeen, half.dir)
	nb := 0
	for p := half.first; p != nil; p = p.next {
		s += fmt.Sprintf("	Page[%d] %s len: %d\n", nb, p, len(p.bytes))
		nb++
	}
	return s
}

/* Bi-directionnal connection */

type connection struct {
	key      key // client->server
	c2s, s2c halfconnection
	mu       sync.Mutex
}

func (c *connection) reset(k key, s Stream, ts time.Time) {
	c.key = k
	base := halfconnection{
		currentTSN: initialTSN,
		created:    ts,
		lastSeen:   ts,
		stream:     s,
	}
	c.c2s, c.s2c = base, base
	c.c2s.dir, c.s2c.dir = SCTPDirClientToServer, SCTPDirServerToClient
}

func (c *connection) lastSeen() time.Time {
	if c.c2s.lastSeen.Before(c.s2c.lastSeen) {
		return c.s2c.lastSeen
	}

	return c.c2s.lastSeen
}

func (c *connection) String() string {
	return fmt.Sprintf("c2s: %s, s2c: %s", &c.c2s, &c.s2c)
}

/*
 * Assembler
 */

// DefaultAssemblerOptions provides default options for an assembler.
// These options are used by default when calling NewAssembler, so if
// modified before a NewAssembler call they'll affect the resulting Assembler.
//
// Note that the default options can result in ever-increasing memory usage
// unless one of the Flush* methods is called on a regular basis.
var DefaultAssemblerOptions = AssemblerOptions{
	MaxBufferedPagesPerConnection: 0, // unlimited
	MaxBufferedPagesTotal:         0, // unlimited
}

// AssemblerOptions controls the behavior of each assembler.  Modify the
// options of each assembler you create to change their behavior.
type AssemblerOptions struct {
	// MaxBufferedPagesTotal is an upper limit on the total number of pages to
	// buffer while waiting for out-of-order packets.  Once this limit is
	// reached, the assembler will degrade to flushing every connection it
	// gets a packet for.  If <= 0, this is ignored.
	MaxBufferedPagesTotal int
	// MaxBufferedPagesPerConnection is an upper limit on the number of pages
	// buffered for a single connection.  Should this limit be reached for a
	// particular connection, the smallest sequence number will be flushed, along
	// with any contiguous data.  If <= 0, this is ignored.
	MaxBufferedPagesPerConnection int
}

// Assembler handles reassembling SCTP streams.  It is not safe for
// concurrency... after passing a packet in via the Assemble call, the caller
// must wait for that call to return before calling Assemble again.  Callers can
// get around this by creating multiple assemblers that share a StreamPool.  In
// that case, each individual stream will still be handled serially (each stream
// has an individual mutex associated with it), however multiple assemblers can
// assemble different connections concurrently.
//
// The Assembler provides (hopefully) fast SCTP stream re-assembly for sniffing
// applications written in Go.  The Assembler uses the following methods to be
// as fast as possible, to keep packet processing speedy:
//
// # Avoids Lock Contention
//
// Assemblers locks connections, but each connection has an individual lock, and
// rarely will two Assemblers be looking at the same connection.  Assemblers
// lock the StreamPool when looking up connections, but they use Reader
// locks initially, and only force a write lock if they need to create a new
// connection or close one down.  These happen much less frequently than
// individual packet handling.
//
// Each assembler runs in its own goroutine, and the only state shared between
// goroutines is through the StreamPool.  Thus all internal Assembler state
// can be handled without any locking.
//
// NOTE:  If you can guarantee that packets going to a set of Assemblers will
// contain information on different connections per Assembler (for example,
// they're already hashed by PF_RING hashing or some other hashing mechanism),
// then we recommend you use a seperate StreamPool per Assembler, thus
// avoiding all lock contention.  Only when different Assemblers could receive
// packets for the same Stream should a StreamPool be shared between them.
//
// # Avoids Memory Copying
//
// In the common case, handling of a single SCTP packet should result in zero
// memory allocations.  The Assembler will look up the connection, figure out
// that the packet has arrived in order, and immediately pass that packet on to
// the appropriate connection's handling code.  Only if a packet arrives out of
// order is its contents copied and stored in memory for later.
//
// # Avoids Memory Allocation
//
// Assemblers try very hard to not use memory allocation unless absolutely
// necessary.  Packet data for sequential packets is passed directly to streams
// with no copying or allocation.  Packet data for out-of-order packets is
// copied into reusable pages, and new pages are only allocated rarely when the
// page cache runs out.  Page caches are Assembler-specific, thus not used
// concurrently and requiring no locking.
//
// Internal representations for connection objects are also reused over time.
// Because of this, the most common memory allocation done by the Assembler is
// generally what's done by the caller in StreamFactory.New.  If no allocation
// is done there, then very little allocation is done ever, mostly to handle
// large increases in bandwidth or numbers of connections.
//
// TODO:  The page caches used by an Assembler will grow to the size necessary
// to handle a workload, and currently will never shrink.  This means that
// traffic spikes can result in large memory usage which isn't garbage
// collected when typical traffic levels return.
type Assembler struct {
	AssemblerOptions
	ret      []byteContainer
	pc       *pageCache
	connPool *StreamPool
	cacheLP  livePacket
	cacheSG  reassemblyObject
	start    bool
}

// NewAssembler creates a new assembler.  Pass in the StreamPool
// to use, may be shared across assemblers.
//
// This sets some sane defaults for the assembler options,
// see DefaultAssemblerOptions for details.
func NewAssembler(pool *StreamPool) *Assembler {
	pool.mu.Lock()
	pool.users++
	pool.mu.Unlock()
	return &Assembler{
		ret:              make([]byteContainer, 0, assemblerReturnValueInitialSize),
		pc:               newPageCache(),
		connPool:         pool,
		AssemblerOptions: DefaultAssemblerOptions,
	}
}

// Dump returns a short string describing the page usage of the Assembler
func (a *Assembler) Dump() string {
	s := ""
	s += fmt.Sprintf("pageCache: used: %d:", a.pc.used)
	return s
}

// AssemblerContext provides method to get metadata
type AssemblerContext interface {
	GetCaptureInfo() gopacket.CaptureInfo
}

// Implements AssemblerContext for Assemble()
type assemblerSimpleContext gopacket.CaptureInfo

func (asc *assemblerSimpleContext) GetCaptureInfo() gopacket.CaptureInfo {
	return gopacket.CaptureInfo(*asc)
}

// // Assemble calls AssembleWithContext with the current timestamp, useful for
// // packets being read directly off the wire.
// func (a *Assembler) Assemble(netFlow gopacket.Flow, t *layers.SCTP) {
// 	ctx := assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: time.Now()})
// 	a.AssembleWithContext(netFlow, t, &ctx)
// }

type assemblerAction struct {
	nextSeq Sequence
	queue   bool
}

// AssembleWithContext reassembles the given SCTP packet into its appropriate
// stream.
//
// The timestamp passed in must be the timestamp the packet was seen.
// For packets read off the wire, time.Now() should be fine.  For packets read
// from PCAP files, CaptureInfo.Timestamp should be passed in.  This timestamp
// will affect which streams are flushed by a call to FlushCloseOlderThan.
//
// Each AssembleWithContext call results in, in order:
//
//	zero or one call to StreamFactory.New, creating a stream
//	zero or one call to ReassembledSG on a single stream
//	zero or one call to ReassemblyComplete on the same stream
func (a *Assembler) AssembleWithContext(packet gopacket.Packet, t *layers.SCTP, ac AssemblerContext) {
	var conn *connection
	var half *halfconnection
	netFlow := packet.NetworkLayer().NetworkFlow()

	var vlanFlow gopacket.Flow
	dot1QLayer := packet.Layer(layers.LayerTypeDot1Q)
	if dot1QLayer != nil {
		packet.SetVlanDot1Q(true)
		packet.SetVlanID(dot1QLayer.(*layers.Dot1Q).VLANIdentifier)
		vlanFlow = dot1QLayer.(*layers.Dot1Q).VLANFlow()
	} else {
		packet.SetVlanDot1Q(false)
		for _, v := range packet.Metadata().AncillaryData {
			if av, ok := v.(gopacket.AncillaryVLAN); ok {
				packet.SetVlanID(uint16(av.VLAN))
				b := make([]byte, 2)
				binary.BigEndian.PutUint16(b, packet.GetVlanID())
				vlanFlow = gopacket.NewFlow(layers.EndpointVLAN, b, b)
			}
		}
	}

	var dataChunks []*layers.SCTPData

	for _, layer := range packet.Layers() {
		switch layer.LayerType() {
		case layers.LayerTypeSCTPData:
			dataChunks = append(dataChunks, packet.Layer(layers.LayerTypeSCTPData).(*layers.SCTPData))
		default:
			continue
		}
	}

	for _, dataChunk := range dataChunks {
		streamIdBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(streamIdBytes, dataChunk.StreamId)
		sctpFlow := gopacket.NewFlow(layers.EndpointSCTPStream, streamIdBytes, streamIdBytes)

		a.ret = a.ret[:0]
		key := key{netFlow, t.TransportFlow(), vlanFlow, sctpFlow}
		ci := ac.GetCaptureInfo()
		timestamp := ci.Timestamp

		conn, half = a.connPool.getConnection(key, false, timestamp, t, ac)
		if conn == nil {
			if *debugLog {
				log.Printf("%v got empty packet on otherwise empty connection", key)
			}
			return
		}
		conn.mu.Lock()
		defer conn.mu.Unlock()

		if half.lastSeen.Before(timestamp) {
			half.lastSeen = timestamp
		}

		a.start = dataChunk.BeginFragment
		if !half.stream.Accept(t, ci, half.dir, half.currentTSN, &a.start, ac) {
			if *debugLog {
				log.Printf("Ignoring packet")
			}
			return
		}
		if half.closed {
			// this way is closed
			if *debugLog {
				log.Printf("%v got packet on closed half", key)
			}
			return
		}

		half.stream.ReceivePacket(packet, t, half.dir)

		tsn, bytes := Sequence(dataChunk.TSN), dataChunk.Payload

		action := assemblerAction{
			nextSeq: Sequence(initialTSN),
			queue:   true,
		}
		a.dump("AssembleWithContext()", half)
		if half.currentTSN == initialTSN {
			if a.start {
				if *debugLog {
					log.Printf("%v start forced", key)
				}
				half.currentTSN = tsn
				action.queue = false
			} else {
				if *debugLog {
					log.Printf("%v waiting for start, storing into connection", key)
				}
			}
		} else {
			diff := half.currentTSN.Difference(tsn)
			if diff > 0 {
				if *debugLog {
					log.Printf("%v gap in sequence numbers (%v, %v) diff %v, storing into connection", key, half.currentTSN, tsn, diff)
				}
			} else {
				if *debugLog {
					log.Printf("%v found contiguous data (%v, %v), returning immediately: len:%d", key, tsn, half.currentTSN, len(bytes))
				}
				action.queue = false
			}
		}

		action = a.handleBytes(bytes, tsn, half, dataChunk.BeginFragment, dataChunk.EndFragment, action, ac)
		if len(a.ret) > 0 {
			a.sendToConnection(conn, half, ac)
			half.currentTSN = tsn
		}
		if *debugLog {
			log.Printf("%v current TSN:%d", key, half.currentTSN)
		}
	}
}

// Warning: this is a low-level dumper, i.e. a.ret or a.cacheSG might
// be strange, but it could be ok.
func (a *Assembler) dump(text string, half *halfconnection) {
	if !*debugLog {
		return
	}
	log.Printf("%s: dump\n", text)
	if half != nil {
		p := half.first
		if p == nil {
			log.Printf(" * half.first = %p, no chunks queued\n", p)
		} else {
			s := 0
			nb := 0
			log.Printf(" * half.first = %p, queued chunks:", p)
			for p != nil {
				log.Printf("\t%s bytes:%s\n", p, hex.EncodeToString(p.bytes))
				s += len(p.bytes)
				nb++
				p = p.next
			}
			log.Printf("\t%d chunks for %d bytes", nb, s)
		}
		log.Printf(" * half.last = %p\n", half.last)
		log.Printf(" * half.saved = %p\n", half.saved)
		p = half.saved
		for p != nil {
			log.Printf("\tseq:%d %s bytes:%s\n", p.getSeq(), p, hex.EncodeToString(p.bytes))
			p = p.next
		}
	}
	log.Printf(" * a.ret\n")
	for i, r := range a.ret {
		log.Printf("\t%d: %v b:%s\n", i, r.captureInfo(), hex.EncodeToString(r.getBytes()))
	}
	log.Printf(" * a.cacheSG.all\n")
	for i, r := range a.cacheSG.all {
		log.Printf("\t%d: %v b:%s\n", i, r.captureInfo(), hex.EncodeToString(r.getBytes()))
	}
}

// Prepare send or queue
func (a *Assembler) handleBytes(bytes []byte, seq Sequence, half *halfconnection, start bool, end bool, action assemblerAction, ac AssemblerContext) assemblerAction {
	a.cacheLP.bytes = bytes
	a.cacheLP.start = start
	a.cacheLP.end = end
	a.cacheLP.seq = seq
	a.cacheLP.ac = ac

	if action.queue {
		if (a.MaxBufferedPagesPerConnection > 0 && half.pages >= a.MaxBufferedPagesPerConnection) ||
			(a.MaxBufferedPagesTotal > 0 && a.pc.used >= a.MaxBufferedPagesTotal) {
			if *debugLog {
				log.Printf("hit max buffer size: %+v, %v, %v", a.AssemblerOptions, half.pages, a.pc.used)
			}
			action.queue = false
			a.addNextFromConn(half)
		}
		a.dump("handleBytes after queue", half)
	} else {
		if len(a.cacheLP.bytes) != 0 || end || start {
			a.ret = append(a.ret, &a.cacheLP)
		}
		a.dump("handleBytes after no queue", half)
	}
	return action
}

func (a *Assembler) setStatsToSG(half *halfconnection) {
	a.cacheSG.queuedBytes = half.queuedBytes
	half.queuedBytes = 0
	a.cacheSG.queuedPackets = half.queuedPackets
	half.queuedPackets = 0
	a.cacheSG.overlapBytes = half.overlapBytes
	half.overlapBytes = 0
	a.cacheSG.overlapPackets = half.overlapPackets
	half.overlapPackets = 0
}

// Build the ScatterGather object, i.e. prepend saved bytes and
// append continuous bytes.
func (a *Assembler) buildSG(half *halfconnection) bool {
	// Prepend saved bytes
	saved := a.addPending(half, a.ret[0].getSeq())
	// Append continuous bytes
	a.cacheSG.all = a.ret
	a.cacheSG.Direction = half.dir
	a.cacheSG.saved = saved
	a.cacheSG.toKeep = -1
	a.setStatsToSG(half)
	a.dump("after buildSG", half)
	return a.ret[len(a.ret)-1].isEnd()
}

func (a *Assembler) cleanSG(half *halfconnection, ac AssemblerContext) {
	cur := 0
	ndx := 0
	skip := 0

	a.dump("cleanSG(start)", half)

	var r byteContainer
	// Find first page to keep
	if a.cacheSG.toKeep < 0 {
		ndx = len(a.cacheSG.all)
	} else {
		skip = a.cacheSG.toKeep
		found := false
		for ndx, r = range a.cacheSG.all {
			if a.cacheSG.toKeep < cur+r.length() {
				found = true
				break
			}
			cur += r.length()
			if skip >= r.length() {
				skip -= r.length()
			}
		}
		if !found {
			ndx++
		}
	}
	// Release consumed pages
	for _, r := range a.cacheSG.all[:ndx] {
		if r == half.saved {
			if half.saved.next != nil {
				half.saved.next.prev = nil
			}
			half.saved = half.saved.next
		} else if r == half.first {
			if half.first.next != nil {
				half.first.next.prev = nil
			}
			if half.first == half.last {
				half.first, half.last = nil, nil
			} else {
				half.first = half.first.next
			}
		}
		half.pages -= r.release(a.pc)
	}
	a.dump("after consumed release", half)
	// Keep un-consumed pages
	nbKept := 0
	half.saved = nil
	var saved *page
	for _, r := range a.cacheSG.all[ndx:] {
		preConvertLen := r.length()
		first, last, nb := r.convertToPages(a.pc, skip, ac)

		// Update skip count as we move from one container to the next.
		if delta := preConvertLen - r.length(); delta > skip {
			skip = 0
		} else {
			skip -= delta
		}

		if half.saved == nil {
			half.saved = first
		} else {
			saved.next = first
			first.prev = saved
		}
		saved = last
		nbKept += nb
	}
	if *debugLog {
		log.Printf("Remaining %d chunks in SG\n", nbKept)
		log.Printf("%s\n", a.Dump())
		a.dump("after cleanSG()", half)
	}
}

// sendToConnection sends the current values in a.ret to the connection, closing
// the connection if the last thing sent had End set.
func (a *Assembler) sendToConnection(conn *connection, half *halfconnection, ac AssemblerContext) {
	if *debugLog {
		log.Printf("sendToConnection\n")
	}
	end := a.buildSG(half)
	half.stream.ReassembledSG(&a.cacheSG, ac)
	a.cleanSG(half, ac)
	if end {
		a.closeHalfConnection(conn, half)
	}
	return
}

func (a *Assembler) addPending(half *halfconnection, firstSeq Sequence) int {
	if half.saved == nil {
		return 0
	}
	s := 0
	ret := []byteContainer{}
	for p := half.saved; p != nil; p = p.next {
		if *debugLog {
			log.Printf("adding pending @%p %s (%s)\n", p, p, hex.EncodeToString(p.bytes))
		}
		ret = append(ret, p)
		s += len(p.bytes)
	}
	if half.saved.seq.Add(s) != firstSeq {
		// non-continuous saved: drop them
		var next *page
		for p := half.saved; p != nil; p = next {
			next = p.next
			p.release(a.pc)
		}
		half.saved = nil
		ret = []byteContainer{}
		s = 0
	}

	a.ret = append(ret, a.ret...)
	return s
}

// skipFlush skips the first set of bytes we're waiting for and returns the
// first set of bytes we have.  If we have no bytes saved, it closes the
// connection.
func (a *Assembler) skipFlush(conn *connection, half *halfconnection) {
	if *debugLog {
		log.Printf("skipFlush %v\n", half.currentTSN)
	}
	// Well, it's embarassing it there is still something in half.saved
	// FIXME: change API to give back saved + new/no packets
	if half.first == nil {
		a.closeHalfConnection(conn, half)
		return
	}
	a.ret = a.ret[:0]
	a.addNextFromConn(half)
	a.sendToConnection(conn, half, a.ret[0].assemblerContext())
}

func (a *Assembler) closeHalfConnection(conn *connection, half *halfconnection) {
	if *debugLog {
		log.Printf("%v closing", conn)
	}
	half.closed = true
	for p := half.first; p != nil; p = p.next {
		// FIXME: it should be already empty
		a.pc.replace(p)
		half.pages--
	}
	if conn.s2c.closed && conn.c2s.closed {
		if half.stream.ReassemblyComplete(nil) { //FIXME: which context to pass ?
			a.connPool.remove(conn)
		}
	}
}

// addNextFromConn pops the first page from a connection off and adds it to the
// return array.
func (a *Assembler) addNextFromConn(conn *halfconnection) {
	if conn.first == nil {
		return
	}
	if *debugLog {
		log.Printf("   adding from conn (%v, %v) %v (%d)\n", conn.first.seq, conn.currentTSN, conn.currentTSN-conn.first.seq, len(conn.first.bytes))
	}
	a.ret = append(a.ret, conn.first)
	conn.first = conn.first.next
	if conn.first != nil {
		conn.first.prev = nil
	} else {
		conn.last = nil
	}
}

// FlushOptions provide options for flushing connections.
type FlushOptions struct {
	T  time.Time // If nonzero, only connections with data older than T are flushed
	TC time.Time // If nonzero, only connections with data older than TC are closed (if no FIN/RST received)
}

// FlushWithOptions finds any streams waiting for packets older than
// the given time T, and pushes through the data they have (IE: tells
// them to stop waiting and skip the data they're waiting for).
//
// It also closes streams older than TC (that can be set to zero, to keep
// long-lived stream alive, but to flush data anyway).
//
// Each Stream maintains a list of zero or more sets of bytes it has received
// out-of-order.  For example, if it has processed up through sequence number
// 10, it might have bytes [15-20), [20-25), [30,50) in its list.  Each set of
// bytes also has the timestamp it was originally viewed.  A flush call will
// look at the smallest subsequent set of bytes, in this case [15-20), and if
// its timestamp is older than the passed-in time, it will push it and all
// contiguous byte-sets out to the Stream's Reassembled function.  In this case,
// it will push [15-20), but also [20-25), since that's contiguous.  It will
// only push [30-50) if its timestamp is also older than the passed-in time,
// otherwise it will wait until the next FlushCloseOlderThan to see if bytes
// [25-30) come in.
//
// Returns the number of connections flushed, and of those, the number closed
// because of the flush.
func (a *Assembler) FlushWithOptions(opt FlushOptions) (flushed, closed int) {
	conns := a.connPool.connections()
	closes := 0
	flushes := 0
	for _, conn := range conns {
		remove := false
		conn.mu.Lock()
		for _, half := range []*halfconnection{&conn.s2c, &conn.c2s} {
			flushed, closed := a.flushClose(conn, half, opt.T, opt.TC)
			if flushed {
				flushes++
			}
			if closed {
				closes++
			}
		}
		if conn.s2c.closed && conn.c2s.closed && conn.s2c.lastSeen.Before(opt.TC) && conn.c2s.lastSeen.Before(opt.TC) {
			remove = true
		}
		conn.mu.Unlock()
		if remove {
			a.connPool.remove(conn)
		}
	}
	return flushes, closes
}

// FlushCloseOlderThan flushes and closes streams older than given time
func (a *Assembler) FlushCloseOlderThan(t time.Time) (flushed, closed int) {
	return a.FlushWithOptions(FlushOptions{T: t, TC: t})
}

func (a *Assembler) flushClose(conn *connection, half *halfconnection, t time.Time, tc time.Time) (bool, bool) {
	flushed, closed := false, false
	if half.closed {
		return flushed, closed
	}
	for half.first != nil && half.first.seen.Before(t) {
		flushed = true
		a.skipFlush(conn, half)
		if half.closed {
			closed = true
			return flushed, closed
		}
	}
	// Close the connection only if both halfs of the connection last seen before tc.
	if !half.closed && half.first == nil && conn.lastSeen().Before(tc) {
		a.closeHalfConnection(conn, half)
		closed = true
	}
	return flushed, closed
}

// FlushAll flushes all remaining data into all remaining connections and closes
// those connections. It returns the total number of connections flushed/closed
// by the call.
func (a *Assembler) FlushAll() (closed int) {
	conns := a.connPool.connections()
	closed = len(conns)
	for _, conn := range conns {
		conn.mu.Lock()
		for _, half := range []*halfconnection{&conn.s2c, &conn.c2s} {
			for !half.closed {
				a.skipFlush(conn, half)
			}
			if !half.closed {
				a.closeHalfConnection(conn, half)
			}
		}
		conn.mu.Unlock()
	}
	return
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
