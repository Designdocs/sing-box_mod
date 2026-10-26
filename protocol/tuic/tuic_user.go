package tuic

import (
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/common/dynamicuser"
	"github.com/sagernet/sing-box/option"
)

func (h *Inbound) setUsers(users []option.TUICUser) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	return h.setUsersLocked(users)
}
func (h *Inbound) setUsersLocked(users []option.TUICUser) error {
	identities := make([]dynamicuser.User, 0, len(users))
	var uuids [][16]byte
	var passwords []string
	for _, user := range users {
		identities = append(identities, dynamicuser.User{Name: user.Name, Secret: user.UUID + "\x00" + user.Password})
		id, err := uuid.FromString(user.UUID)
		if err != nil {
			return err
		}
		uuids = append(uuids, id)
		passwords = append(passwords, user.Password)
	}
	err := h.usersState.Update(identities, func() error { h.server.UpdateUsers(identities, uuids, passwords); return nil })
	if err == nil {
		h.users = append([]option.TUICUser(nil), users...)
	}
	return err
}
func (h *Inbound) AddUsers(users []option.TUICUser, _ []int) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	return h.setUsersLocked(append(append([]option.TUICUser(nil), h.users...), users...))
}
func (h *Inbound) DelUsers(names []string) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	removed := make(map[string]bool, len(names))
	for _, name := range names {
		removed[name] = true
	}
	users := make([]option.TUICUser, 0, len(h.users))
	for _, user := range h.users {
		if !removed[user.Name] {
			users = append(users, user)
		}
	}
	return h.setUsersLocked(users)
}
