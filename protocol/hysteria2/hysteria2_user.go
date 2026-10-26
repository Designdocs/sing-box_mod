package hysteria2

import (
	"github.com/sagernet/sing-box/common/dynamicuser"
	"github.com/sagernet/sing-box/option"
)

func (h *Inbound) setUsers(users []option.Hysteria2User) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	return h.setUsersLocked(users)
}
func (h *Inbound) setUsersLocked(users []option.Hysteria2User) error {
	identities := make([]dynamicuser.User, 0, len(users))
	var passwords []string
	for _, user := range users {
		identities = append(identities, dynamicuser.User{Name: user.Name, Secret: user.Password})
		passwords = append(passwords, user.Password)
	}
	err := h.usersState.Update(identities, func() error { h.service.UpdateUsers(identities, passwords); return nil })
	if err == nil {
		h.users = append([]option.Hysteria2User(nil), users...)
	}
	return err
}
func (h *Inbound) AddUsers(users []option.Hysteria2User, _ []int) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	return h.setUsersLocked(append(append([]option.Hysteria2User(nil), h.users...), users...))
}
func (h *Inbound) DelUsers(names []string) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	removed := make(map[string]bool, len(names))
	for _, name := range names {
		removed[name] = true
	}
	users := make([]option.Hysteria2User, 0, len(h.users))
	for _, user := range h.users {
		if !removed[user.Name] {
			users = append(users, user)
		}
	}
	return h.setUsersLocked(users)
}
