package main

import (
	"bytes"
	"testing"
)

func TestMyBuildAndReadPacket(t *testing.T) {
	payload := []byte{myCOMQuery}
	payload = append(payload, "SELECT * FROM users"...)

	pkt := myBuildPacket(0, payload)

	got, err := myReadPacket(bytes.NewReader(pkt))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, pkt) {
		t.Error("packet round-trip mismatch")
	}
}

func TestMyPacketLen(t *testing.T) {
	payload := []byte("hello world")
	pkt := myBuildPacket(1, payload)

	gotLen := myPacketLen(pkt)
	if gotLen != uint32(len(payload)) {
		t.Errorf("myPacketLen = %d, want %d", gotLen, len(payload))
	}
}

func TestMyPacketSeq(t *testing.T) {
	pkt := myBuildPacket(42, []byte("x"))
	if got := myPacketSeq(pkt); got != 42 {
		t.Errorf("myPacketSeq = %d, want 42", got)
	}
}

func TestMyExtractSQL(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{
			name:    "COM_QUERY",
			payload: append([]byte{myCOMQuery}, "SELECT 1"...),
			want:    "SELECT 1",
		},
		{
			name:    "COM_STMT_PREPARE",
			payload: append([]byte{myCOMStmtPrepare}, "INSERT INTO t VALUES (?)"...),
			want:    "INSERT INTO t VALUES (?)",
		},
		{
			name:    "other command",
			payload: []byte{0x01, 0x00}, // COM_QUIT
			want:    "",
		},
		{
			name:    "empty",
			payload: nil,
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := myExtractSQL(tt.payload)
			if got != tt.want {
				t.Errorf("myExtractSQL = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMyErrPacket(t *testing.T) {
	var buf bytes.Buffer
	myWriteErrPacket(&buf, 1, "blocked")

	pkt, err := myReadPacket(&buf)
	if err != nil {
		t.Fatal(err)
	}

	payload := myPayload(pkt)
	if len(payload) == 0 || payload[0] != 0xFF {
		t.Error("expected ERR_Packet marker 0xFF")
	}
	if !bytes.Contains(payload, []byte("blocked")) {
		t.Error("error message not found in ERR_Packet")
	}
}

func TestMyCOMQueryPacket(t *testing.T) {
	// Build a COM_QUERY packet and verify the SQL can be extracted.
	sql := "UPDATE users SET email='test@example.com' WHERE id=1"
	payload := append([]byte{myCOMQuery}, sql...)
	pkt := myBuildPacket(0, payload)

	// Read it back and extract.
	got, err := myReadPacket(bytes.NewReader(pkt))
	if err != nil {
		t.Fatal(err)
	}

	gotSQL := myExtractSQL(myPayload(got))
	if gotSQL != sql {
		t.Errorf("round-trip SQL = %q, want %q", gotSQL, sql)
	}

	gotVerb := sqlVerb(gotSQL)
	if gotVerb != "UPDATE" {
		t.Errorf("sqlVerb = %q, want UPDATE", gotVerb)
	}
}
