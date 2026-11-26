# GoPacket

This library provides packet decoding capabilities for Go.
See [godoc](https://godoc.org/github.com/kubeshark/gopacket) for more details.

[![Build Status](https://travis-ci.org/google/gopacket.svg?branch=master)](https://travis-ci.org/google/gopacket)
[![GoDoc](https://godoc.org/github.com/kubeshark/gopacket?status.svg)](https://godoc.org/github.com/kubeshark/gopacket)

Minimum Go version required is 1.5 except for pcapgo/EthernetHandle, afpacket, and bsdbpf which need at least 1.9 due to x/sys/unix dependencies.

Originally forked from the gopcap project written by Andreas
Krennmair <ak@synflood.at> (http://github.com/akrennmair/gopcap).

## Selective TCP flushing

`reassembly.Assembler.FlushWithOptionsIf` applies flush and close thresholds only
to streams accepted by its predicate. Excluded streams remain unchanged; a nil
predicate behaves like `FlushWithOptions`. Callers must serialize assembler access,
and predicates must not call back into the assembler.

The public-API contract tests run with `go test -race ./integration/reassembly`.
