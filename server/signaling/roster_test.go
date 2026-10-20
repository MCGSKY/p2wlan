package signaling

import "testing"

func TestRoomRosterHintRejectsDifferentAuthenticatedNetwork(t *testing.T) {
	fixture := newWebSocketFixture(t)
	conn := fixture.dial(t, "")
	ready := readServerMessage(t, conn)
	if fixture.hub.NotifyRoomRoster(fixture.deviceID, "another-room") {
		t.Fatal("roster hint crossed authenticated network scope")
	}
	if fixture.hub.NotifyRoomRoster(fixture.deviceID, "") {
		t.Fatal("empty room hint was admitted")
	}
	if !fixture.hub.NotifyRoomRoster(fixture.deviceID, ready.NetworkID) {
		t.Fatal("same-network legacy notification was not admitted")
	}
	notification := readServerMessage(t, conn)
	if notification.Type != "signals_available" || notification.Sequence != 1 {
		t.Fatalf("invalid hints altered the original sequence or legacy transport: %+v", notification)
	}
}
