package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildBSONDoc builds a minimal BSON document from key-value string pairs.
// Only supports string values (type 0x02).
func buildBSONDoc(pairs ...string) []byte {
	if len(pairs)%2 != 0 {
		panic("odd number of arguments to buildBSONDoc")
	}
	var buf bytes.Buffer
	buf.Write(make([]byte, 4)) // placeholder for length

	for i := 0; i < len(pairs); i += 2 {
		key := pairs[i]
		val := pairs[i+1]

		buf.WriteByte(0x02) // string type
		buf.WriteString(key)
		buf.WriteByte(0)
		valBytes := val + "\x00"
		binary.Write(&buf, binary.LittleEndian, int32(len(valBytes)))
		buf.WriteString(valBytes)
	}
	buf.WriteByte(0) // document terminator

	doc := buf.Bytes()
	binary.LittleEndian.PutUint32(doc[:4], uint32(len(doc)))
	return doc
}

// buildOPMsg builds a minimal OP_MSG with a single kind-0 section.
func buildOPMsg(requestID uint32, doc []byte) []byte {
	totalLen := mgHeaderLen + 4 + 1 + len(doc) // header + flags + kind + doc
	msg := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(msg[4:8], requestID)
	// responseTo = 0
	binary.LittleEndian.PutUint32(msg[12:16], uint32(mgOpMsg))
	// flags = 0 (4 bytes already zero)
	msg[mgHeaderLen+4] = 0 // kind 0
	copy(msg[mgHeaderLen+5:], doc)
	return msg
}

func TestMgExtractCommand(t *testing.T) {
	tests := []struct {
		name     string
		doc      []byte
		wantCmd  string
		wantColl string
		wantDB   string
	}{
		{
			name:     "find command",
			doc:      buildBSONDoc("find", "users", "$db", "mydb"),
			wantCmd:  "find",
			wantColl: "users",
			wantDB:   "mydb",
		},
		{
			name:     "insert command",
			doc:      buildBSONDoc("insert", "orders", "$db", "shop"),
			wantCmd:  "insert",
			wantColl: "orders",
			wantDB:   "shop",
		},
		{
			name:     "aggregate",
			doc:      buildBSONDoc("aggregate", "events", "$db", "analytics"),
			wantCmd:  "aggregate",
			wantColl: "events",
			wantDB:   "analytics",
		},
		{
			name:    "empty doc",
			doc:     []byte{5, 0, 0, 0, 0}, // minimal empty BSON
			wantCmd: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, coll, db := mgExtractCommand(tt.doc)
			if cmd != tt.wantCmd {
				t.Errorf("command = %q, want %q", cmd, tt.wantCmd)
			}
			if coll != tt.wantColl {
				t.Errorf("collection = %q, want %q", coll, tt.wantColl)
			}
			if db != tt.wantDB {
				t.Errorf("db = %q, want %q", db, tt.wantDB)
			}
		})
	}
}

func TestMgReadMessage(t *testing.T) {
	doc := buildBSONDoc("find", "users", "$db", "test")
	msg := buildOPMsg(1, doc)

	got, err := mgReadMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Error("message round-trip mismatch")
	}
}

func TestMgReadMessageLength(t *testing.T) {
	doc := buildBSONDoc("insert", "logs", "$db", "appdb")
	msg := buildOPMsg(42, doc)

	gotLen := binary.LittleEndian.Uint32(msg[:4])
	if int(gotLen) != len(msg) {
		t.Errorf("message length header = %d, actual = %d", gotLen, len(msg))
	}
}

func TestMgSendError(t *testing.T) {
	// Build a request to get a requestID for the error response.
	doc := buildBSONDoc("find", "x", "$db", "test")
	request := buildOPMsg(99, doc)

	var buf bytes.Buffer
	mgSendError(&buf, request, "blocked by policy")

	resp, err := mgReadMessage(&buf)
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's an OP_MSG.
	opCode := int32(binary.LittleEndian.Uint32(resp[12:16]))
	if opCode != mgOpMsg {
		t.Errorf("opCode = %d, want %d", opCode, mgOpMsg)
	}

	// Verify responseTo matches requestID.
	responseTo := binary.LittleEndian.Uint32(resp[8:12])
	if responseTo != 99 {
		t.Errorf("responseTo = %d, want 99", responseTo)
	}

	// Verify the error message appears in the body.
	if !bytes.Contains(resp, []byte("blocked by policy")) {
		t.Error("error message not found in response")
	}
}

func TestParseDBURL(t *testing.T) {
	tests := []struct {
		raw, name    string
		wantHost     string
		wantPort     string
		wantProtocol string
	}{
		{
			raw:      "postgresql://user:pass@db.example.com:5432/mydb",
			wantHost: "db.example.com", wantPort: "5432", wantProtocol: "postgresql",
		},
		{
			raw:      "postgres://db.example.com/mydb",
			wantHost: "db.example.com", wantPort: "5432", wantProtocol: "postgresql",
		},
		{
			raw:      "mysql://mysql.example.com:3306/shop",
			wantHost: "mysql.example.com", wantPort: "3306", wantProtocol: "mysql",
		},
		{
			raw:      "mongodb://mongo.example.com:27017/analytics",
			wantHost: "mongo.example.com", wantPort: "27017", wantProtocol: "mongodb",
		},
		{
			raw:      "mongodb+srv://cluster.mongodb.net/test",
			wantHost: "cluster.mongodb.net", wantPort: "27017", wantProtocol: "mongodb",
		},
		{
			raw: "neon-db.us-east-2.aws.neon.tech", name: "neondb",
			wantHost: "neon-db.us-east-2.aws.neon.tech", wantPort: "5432", wantProtocol: "postgresql",
		},
		{
			raw: "my-mysql.example.com", name: "mysql-prod",
			wantHost: "my-mysql.example.com", wantPort: "3306", wantProtocol: "mysql",
		},
		{
			raw: "docdb-cluster.cluster-xxx.us-east-1.docdb.amazonaws.com", name: "documents",
			wantHost: "docdb-cluster.cluster-xxx.us-east-1.docdb.amazonaws.com", wantPort: "27017", wantProtocol: "mongodb",
		},
		{
			raw: "https://ep-round-darkness.us-east-1.aws.neon.tech", name: "neon",
			wantHost: "ep-round-darkness.us-east-1.aws.neon.tech", wantPort: "5432", wantProtocol: "postgresql",
		},
		{
			raw: "https://db.xxxx.supabase.co", name: "supabase",
			wantHost: "db.xxxx.supabase.co", wantPort: "5432", wantProtocol: "postgresql",
		},
		{
			raw: "https://db.xxxx.supabase.co:5432", name: "supabase-port",
			wantHost: "db.xxxx.supabase.co", wantPort: "5432", wantProtocol: "postgresql",
		},
		{
			raw:      "mongodb+srv://doadmin:pass@db-mongodb-nyc3.mongo.ondigitalocean.com",
			wantHost: "db-mongodb-nyc3.mongo.ondigitalocean.com", wantPort: "27017", wantProtocol: "mongodb",
		},
		{
			raw: "https://db-mongodb-nyc3.mongo.ondigitalocean.com", name: "do-mongo",
			wantHost: "db-mongodb-nyc3.mongo.ondigitalocean.com", wantPort: "27017", wantProtocol: "mongodb",
		},
		// AWS RDS — hostname alone does not reveal the protocol.
		// Port-based detection catches MySQL on port 3306.
		{
			raw: "https://mydb.cluster-xxx.us-east-1.rds.amazonaws.com:5432", name: "rds-pg",
			wantHost: "mydb.cluster-xxx.us-east-1.rds.amazonaws.com", wantPort: "5432", wantProtocol: "postgresql",
		},
		{
			raw: "https://mydb.cluster-xxx.us-east-1.rds.amazonaws.com:3306", name: "rds-mysql",
			wantHost: "mydb.cluster-xxx.us-east-1.rds.amazonaws.com", wantPort: "3306", wantProtocol: "mysql",
		},
		// Azure Database — hostname contains "mysql" or "postgres".
		{
			raw: "https://myserver.mysql.database.azure.com:3306", name: "azure-my",
			wantHost: "myserver.mysql.database.azure.com", wantPort: "3306", wantProtocol: "mysql",
		},
		{
			raw: "https://myserver.postgres.database.azure.com:5432", name: "azure-pg",
			wantHost: "myserver.postgres.database.azure.com", wantPort: "5432", wantProtocol: "postgresql",
		},
		// GCP Cloud SQL — hostname is an IP, port decides protocol.
		{
			raw: "https://34.123.45.67:3306", name: "gcp-mysql",
			wantHost: "34.123.45.67", wantPort: "3306", wantProtocol: "mysql",
		},
		// PlanetScale — psdb.cloud hostname.
		{
			raw: "https://us-east.connect.psdb.cloud:3306", name: "planetscale",
			wantHost: "us-east.connect.psdb.cloud", wantPort: "3306", wantProtocol: "mysql",
		},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			host, port, proto := parseDBURL(tt.raw, tt.name)
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("port = %q, want %q", port, tt.wantPort)
			}
			if proto != tt.wantProtocol {
				t.Errorf("protocol = %q, want %q", proto, tt.wantProtocol)
			}
		})
	}
}
