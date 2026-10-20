package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
	"github.com/yhan-sun/p2wlan/server/signaling"
)

func TestRoomLeavePublishesRosterWakeAfterCommit(t *testing.T) {
	for _, capable := range []bool{true, false} {
		name := "negotiated"
		if !capable {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			db, err := database.New(filepath.Join(t.TempDir(), "rooms.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			service := auth.NewService("test-room-roster-wake", db)
			_, owner, err := service.Register("owner@roster.test", "account-password")
			if err != nil {
				t.Fatal(err)
			}
			memberToken, member, err := service.Register("member@roster.test", "account-password")
			if err != nil {
				t.Fatal(err)
			}
			room, err := db.CreateRoom(owner.ID, "room", "safe-password")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.JoinRoom(member.ID, room.Code, "safe-password", ""); err != nil {
				t.Fatal(err)
			}
			survivor, err := db.CreateDevice(owner.ID, room.ID, "survivor-key", "survivor", "linux", "")
			if err != nil {
				t.Fatal(err)
			}
			departing, err := db.CreateDevice(member.ID, room.ID, "departing-key", "departing", "linux", "")
			if err != nil {
				t.Fatal(err)
			}
			_, credential, err := db.CreateDeviceCredential(survivor.ID, 3600)
			if err != nil {
				t.Fatal(err)
			}
			hub := signaling.NewHub()
			defer hub.Close()
			ws := httptest.NewServer(auth.RequireDeviceAuth(db)(signaling.ServeWS(hub)))
			defer ws.Close()
			dialer := websocket.Dialer{HandshakeTimeout: 2 * time.Second, Subprotocols: []string{signaling.ProtocolName}}
			header := http.Header{"Authorization": []string{"Bearer " + credential}}
			if capable {
				header.Set("X-P2WLAN-Room-Roster-Wake", "1")
			}
			conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(ws.URL, "http"), header)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			var ready map[string]any
			if err := conn.ReadJSON(&ready); err != nil {
				t.Fatal(err)
			}
			if ready["node_id"] != survivor.ID || ready["network_id"] != room.ID {
				t.Fatal("unbound ready identity")
			}
			api := NewServer(service, hub, db)
			mux := http.NewServeMux()
			api.RegisterRoomRoutes(mux)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/rooms/"+room.ID+"/leave", nil)
			req.Header.Set("Authorization", "Bearer "+memberToken)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("leave status=%d", rec.Code)
			}
			devices, err := db.ListDevicesByNetwork(room.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, device := range devices {
				if device.ID == departing.ID {
					t.Fatal("wake preceded committed membership removal")
				}
			}
			var notification map[string]any
			if err := conn.ReadJSON(&notification); err != nil {
				t.Fatal(err)
			}
			expected := "signals_available"
			if capable {
				expected = "roster_changed"
			}
			if notification["type"] != expected || notification["sequence"] != float64(1) {
				t.Fatalf("unexpected committed roster wake: type=%v seq=%v", notification["type"], notification["sequence"])
			}
			if capable && (notification["node_id"] != survivor.ID || notification["network_id"] != room.ID) {
				t.Fatal("roster wake lacks authenticated room/device scope")
			}
		})
	}
}
