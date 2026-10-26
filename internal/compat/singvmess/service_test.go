package vmess

import "testing"

func TestDynamicLegacyUsersKeepReplayStateAndCloseOnce(t *testing.T) {
	service := NewService[string](nil)
	if err := service.UpdateUsers(nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	token := []byte("a request already accepted")
	if !service.replayFilter.Check(token) {
		t.Fatal("first request rejected")
	}
	if err := service.UpdateUsers([]string{"user"}, []string{"11111111-1111-1111-1111-111111111111"}, []int{1}); err != nil {
		t.Fatal(err)
	}
	if service.alterIdUpdateTask == nil || !service.users.Load().hasLegacy {
		t.Fatal("adding a legacy user after start did not enable key refresh")
	}
	if service.replayFilter.Check(token) {
		t.Fatal("updating users reset the replay filter")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}
