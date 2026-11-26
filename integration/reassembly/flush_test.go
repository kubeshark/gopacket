package reassembly_test

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/reassembly"
	"github.com/kubeshark/tracerproto/pkg/unixpacket"
)

type flushTestDelivery struct {
	data string
	skip int
}

type flushTestStream struct {
	deliveries [2][]flushTestDelivery
	completed  int
	accepted   int
	keepClosed bool
}

func (s *flushTestStream) Accept(_ *layers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, _ reassembly.Sequence, _ *bool, _ reassembly.AssemblerContext) bool {
	s.accepted++
	return true
}

func (s *flushTestStream) ReceivePacket(gopacket.Packet, *layers.TCP, reassembly.TCPFlowDirection) {}

func (s *flushTestStream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	dir, _, _, skip := sg.Info()
	index := 0
	if dir == reassembly.TCPDirServerToClient {
		index = 1
	}
	length, _ := sg.Lengths()
	s.deliveries[index] = append(s.deliveries[index], flushTestDelivery{string(sg.Fetch(length)), skip})
}

func (s *flushTestStream) ReassemblyComplete(reassembly.AssemblerContext) bool {
	s.completed++
	return !s.keepClosed
}

type flushTestFactory struct {
	streams map[layers.TCPPort]*flushTestStream
	created int
}

func (f *flushTestFactory) New(_, _ gopacket.Flow, tcp *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	s := &flushTestStream{}
	f.streams[tcp.SrcPort] = s
	f.created++
	return s
}

type flushTestContext struct {
	timestamp time.Time
}

func (c flushTestContext) GetCaptureInfo() gopacket.CaptureInfo {
	return gopacket.CaptureInfo{Timestamp: c.timestamp}
}

func assembleFlushTestPacket(t *testing.T, a *reassembly.Assembler, port layers.TCPPort, reverse bool, seq uint32, syn, fin bool, payload string, timestamp time.Time) {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IP{1, 2, 3, 4}, DstIP: net.IP{5, 6, 7, 8}}
	tcp := &layers.TCP{SrcPort: port, DstPort: 80, Seq: seq, SYN: syn, FIN: fin}
	if reverse {
		ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
		tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true}, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default, 0, unixpacket.PacketSent)
	if err := packet.ErrorLayer(); err != nil {
		t.Fatal(err.Error())
	}
	a.AssembleWithContext(packet, packet.TransportLayer().(*layers.TCP), flushTestContext{timestamp})
}

func queueFlushTestGap(t *testing.T, a *reassembly.Assembler, port layers.TCPPort, timestamp time.Time) {
	t.Helper()
	for _, dir := range []struct {
		reverse bool
		prefix  string
		tail    string
		next    string
	}{
		{false, "abc", "ghi", "jkl"},
		{true, "ABC", "GHI", "JKL"},
	} {
		assembleFlushTestPacket(t, a, port, dir.reverse, 100, true, false, dir.prefix, timestamp)
		assembleFlushTestPacket(t, a, port, dir.reverse, 107, false, false, dir.tail, timestamp.Add(100*time.Millisecond))
		// Contiguous bytes must accompany the older page, even when newer than T.
		assembleFlushTestPacket(t, a, port, dir.reverse, 110, false, false, dir.next, timestamp.Add(200*time.Millisecond))
	}
}

func wantFlushTestDeliveries(t *testing.T, s *flushTestStream, want [2][]flushTestDelivery) {
	t.Helper()
	if !reflect.DeepEqual(s.deliveries, want) {
		t.Fatalf("deliveries = %#v, want %#v", s.deliveries, want)
	}
}

func TestFlushWithOptionsIfPreservesExcludedReordering(t *testing.T) {
	for _, closeSelected := range []bool{false, true} {
		name := "keep_alive"
		if closeSelected {
			name = "close_stale"
		}
		t.Run(name, func(t *testing.T) {
			factory := &flushTestFactory{streams: make(map[layers.TCPPort]*flushTestStream)}
			a := reassembly.NewAssembler(reassembly.NewStreamPool(factory))
			now := time.Unix(1000, 0)
			queueFlushTestGap(t, a, 1234, now)
			queueFlushTestGap(t, a, 1235, now)
			selected, excluded := factory.streams[1234], factory.streams[1235]
			opt := reassembly.FlushOptions{T: now.Add(150 * time.Millisecond)}
			wantClosed := 0
			if closeSelected {
				opt.TC = now.Add(time.Second)
				wantClosed = 2
			}
			calls := make(map[reassembly.Stream]int)
			flushed, closed := a.FlushWithOptionsIf(opt, func(s reassembly.Stream) bool {
				calls[s]++
				return s == selected
			})
			if flushed != 2 || closed != wantClosed {
				t.Fatalf("flush counts = (%d, %d), want (2, %d)", flushed, closed, wantClosed)
			}
			if len(calls) != 2 || calls[selected] != 1 || calls[excluded] != 1 {
				t.Fatalf("predicate calls = %v, want once per stream", calls)
			}
			wantFlushTestDeliveries(t, selected, [2][]flushTestDelivery{
				{{"abc", 0}, {"ghijkl", 3}},
				{{"ABC", 0}, {"GHIJKL", 3}},
			})
			wantFlushTestDeliveries(t, excluded, [2][]flushTestDelivery{
				{{"abc", 0}},
				{{"ABC", 0}},
			})
			if excluded.completed != 0 || selected.completed != wantClosed/2 {
				t.Fatalf("completion counts: selected=%d excluded=%d", selected.completed, excluded.completed)
			}

			assembleFlushTestPacket(t, a, 1235, false, 104, false, false, "def", now.Add(2*time.Second))
			assembleFlushTestPacket(t, a, 1235, true, 104, false, false, "DEF", now.Add(2*time.Second))
			wantFlushTestDeliveries(t, excluded, [2][]flushTestDelivery{
				{{"abc", 0}, {"defghijkl", 0}},
				{{"ABC", 0}, {"DEFGHIJKL", 0}},
			})
			if factory.created != 2 || excluded.completed != 0 {
				t.Fatalf("excluded stream replaced or closed: created=%d completed=%d", factory.created, excluded.completed)
			}
		})
	}
}

func TestFlushWithOptionsCompatibility(t *testing.T) {
	for _, method := range []string{"original", "nil_predicate", "include_all", "close_older_than"} {
		t.Run(method, func(t *testing.T) {
			factory := &flushTestFactory{streams: make(map[layers.TCPPort]*flushTestStream)}
			a := reassembly.NewAssembler(reassembly.NewStreamPool(factory))
			now := time.Unix(1000, 0)
			queueFlushTestGap(t, a, 1234, now)
			stream := factory.streams[1234]
			flush := func(opt reassembly.FlushOptions) (int, int) {
				switch method {
				case "nil_predicate":
					return a.FlushWithOptionsIf(opt, nil)
				case "include_all":
					return a.FlushWithOptionsIf(opt, func(reassembly.Stream) bool { return true })
				case "close_older_than":
					return a.FlushCloseOlderThan(opt.T)
				default:
					return a.FlushWithOptions(opt)
				}
			}
			for _, cutoff := range []time.Time{{}, now.Add(100 * time.Millisecond)} {
				if flushed, closed := flush(reassembly.FlushOptions{T: cutoff}); flushed != 0 || closed != 0 {
					t.Fatalf("non-expired flush counts = (%d, %d), want (0, 0)", flushed, closed)
				}
			}
			if flushed, closed := flush(reassembly.FlushOptions{T: now.Add(150 * time.Millisecond)}); flushed != 2 || closed != 0 {
				t.Fatalf("gap flush counts = (%d, %d), want (2, 0)", flushed, closed)
			}
			wantFlushTestDeliveries(t, stream, [2][]flushTestDelivery{
				{{"abc", 0}, {"ghijkl", 3}},
				{{"ABC", 0}, {"GHIJKL", 3}},
			})
			if stream.completed != 0 {
				t.Fatal("active stream closed during gap flush")
			}
			assembleFlushTestPacket(t, a, 1234, false, 113, false, false, "mno", now.Add(time.Second))
			wantFlushTestDeliveries(t, stream, [2][]flushTestDelivery{
				{{"abc", 0}, {"ghijkl", 3}, {"mno", 0}},
				{{"ABC", 0}, {"GHIJKL", 3}},
			})
			cutoff := now.Add(2 * time.Second)
			if flushed, closed := flush(reassembly.FlushOptions{T: cutoff, TC: cutoff}); flushed != 0 || closed != 2 {
				t.Fatalf("stale flush counts = (%d, %d), want (0, 2)", flushed, closed)
			}
			if stream.completed != 1 {
				t.Fatalf("stale stream completion count = %d, want 1", stream.completed)
			}
			assembleFlushTestPacket(t, a, 1234, false, 300, true, false, "new", cutoff)
			if factory.created != 2 || factory.streams[1234] == stream {
				t.Fatal("stale stream not removed")
			}
		})
	}
}

func TestFlushWithOptionsIfPreservesExcludedClosedStream(t *testing.T) {
	factory := &flushTestFactory{streams: make(map[layers.TCPPort]*flushTestStream)}
	a := reassembly.NewAssembler(reassembly.NewStreamPool(factory))
	now := time.Unix(1000, 0)
	assembleFlushTestPacket(t, a, 1234, false, 100, true, false, "abc", now)
	stream := factory.streams[1234]
	stream.keepClosed = true
	assembleFlushTestPacket(t, a, 1234, true, 100, true, false, "ABC", now)
	assembleFlushTestPacket(t, a, 1234, false, 104, false, true, "", now)
	assembleFlushTestPacket(t, a, 1234, true, 104, false, true, "", now)
	if stream.completed != 1 {
		t.Fatalf("completion count = %d, want 1", stream.completed)
	}
	cutoff := now.Add(time.Second)
	opt := reassembly.FlushOptions{T: cutoff, TC: cutoff}
	if flushed, closed := a.FlushWithOptionsIf(opt, func(reassembly.Stream) bool { return false }); flushed != 0 || closed != 0 {
		t.Fatalf("excluded closed stream counts = (%d, %d), want (0, 0)", flushed, closed)
	}
	accepted := stream.accepted
	assembleFlushTestPacket(t, a, 1234, false, 105, false, false, "late", now)
	if factory.created != 1 || stream.accepted != accepted+1 || stream.completed != 1 {
		t.Fatal("excluded closed stream no longer receives late packets")
	}
	if flushed, closed := a.FlushWithOptionsIf(opt, nil); flushed != 0 || closed != 0 {
		t.Fatalf("already closed stream counts = (%d, %d), want (0, 0)", flushed, closed)
	}
	assembleFlushTestPacket(t, a, 1234, false, 300, true, false, "new", cutoff)
	if factory.created != 2 || factory.streams[1234] == stream {
		t.Fatal("included stale closed stream not removed")
	}
}
