package vless

import (
	"github.com/sagernet/sing-box/common/dynamicuser"
	"github.com/sagernet/sing-box/option"
)

func (h *Inbound) setUsers(users []option.VLESSUser) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	return h.setUsersLocked(users)
}
func (h *Inbound) setUsersLocked(users []option.VLESSUser) error {
	identities := make([]dynamicuser.User, 0, len(users))
	var uuids, flows []string
	for _, user := range users {
		identities = append(identities, dynamicuser.User{Name: user.Name, Secret: user.UUID + "\x00" + user.Flow})
		uuids = append(uuids, user.UUID)
		flows = append(flows, user.Flow)
	}
	err := h.usersState.Update(identities, func() error { h.service.UpdateUsers(identities, uuids, flows); return nil })
	if err == nil {
		h.users = append([]option.VLESSUser(nil), users...)
	}
	return err
}
func (h *Inbound) AddUsers(users []option.VLESSUser) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	return h.setUsersLocked(append(append([]option.VLESSUser(nil), h.users...), users...))
}
func (h *Inbound) DelUsers(names []string) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	removed := make(map[string]bool, len(names))
	for _, name := range names {
		removed[name] = true
	}
	users := make([]option.VLESSUser, 0, len(h.users))
	for _, user := range h.users {
		if !removed[user.Name] {
			users = append(users, user)
		}
	}
	return h.setUsersLocked(users)
}
