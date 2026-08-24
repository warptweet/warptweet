package inspectnet

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParseRouteMessagesUsesRTATableOverRtmTable(t *testing.T) {
	t.Parallel()

	pref := netip.MustParseAddr("10.168.0.2").As4()
	tableAttr := make([]byte, 4)
	binary.LittleEndian.PutUint32(tableAttr, 100)
	oif := make([]byte, 4)
	binary.LittleEndian.PutUint32(oif, 2)

	payload := make([]byte, rtmsgLen)
	payload[0] = FamilyIPv4
	payload[4] = rtTableMain
	payload = appendRTAttr(payload, rtaPrefSrc, pref[:])
	payload = appendRTAttr(payload, rtaOif, oif)
	payload = appendRTAttr(payload, rtaTable, tableAttr)

	msg := make([]byte, nlmsgHdrLen+len(payload))
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:6], rtmNewRoute)
	copy(msg[nlmsgHdrLen:], payload)

	reply, err := ParseRouteMessages(msg)
	if err != nil {
		t.Fatal(err)
	}
	if countNewRoute(reply) != 1 {
		t.Fatalf("messages = %+v", reply.Messages)
	}
	got := reply.Messages[0]
	if got.Table != 100 {
		t.Fatalf("table = %d, want 100 from RTA_TABLE (rtm_table was %d)", got.Table, rtTableMain)
	}
	if !got.HasPrefSrc || got.PrefSrc != netip.MustParseAddr("10.168.0.2") {
		t.Fatalf("prefsrc = %+v", got)
	}
	if !got.HasOutIf || got.OutIfIndex != 2 {
		t.Fatalf("oif = %+v", got)
	}
}

func TestParseRouteMessagesUsesRtmTableWhenRTATableAbsent(t *testing.T) {
	t.Parallel()

	payload := make([]byte, rtmsgLen)
	payload[0] = FamilyIPv4
	payload[4] = rtTableMain
	msg := make([]byte, nlmsgHdrLen+len(payload))
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:6], rtmNewRoute)
	copy(msg[nlmsgHdrLen:], payload)

	reply, err := ParseRouteMessages(msg)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Messages[0].Table != uint32(rtTableMain) {
		t.Fatalf("table = %d", reply.Messages[0].Table)
	}
}

func appendRTAttr(buf []byte, typ int, val []byte) []byte {
	rtaLen := rtattrHdrLen + len(val)
	attr := make([]byte, nlmsgAlign(rtaLen))
	binary.LittleEndian.PutUint16(attr[0:2], uint16(rtaLen))
	binary.LittleEndian.PutUint16(attr[2:4], uint16(typ))
	copy(attr[rtattrHdrLen:], val)
	return append(buf, attr...)
}
