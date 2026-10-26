package shadowsocks

import (
	"github.com/sagernet/sing-box/common/dynamicuser"
	"github.com/sagernet/sing-box/option"
)

func (h *MultiInbound) setUsers(users []option.ShadowsocksUser) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	return h.setUsersLocked(users)
}
func (h *MultiInbound) setUsersLocked(users []option.ShadowsocksUser) error {
	identities := make([]dynamicuser.User, 0, len(users))
	var passwords []string
	for _, user := range users {
		identities = append(identities, dynamicuser.User{Name: user.Name, Secret: user.Password})
		passwords = append(passwords, user.Password)
	}
	err := h.usersState.Update(identities, func() error { return h.service.UpdateUsersWithPasswords(identities, passwords) })
	if err == nil {
		h.users = append([]option.ShadowsocksUser(nil), users...)
	}
	return err
}
func (h *MultiInbound) AddUsers(users []option.ShadowsocksUser) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	return h.setUsersLocked(append(append([]option.ShadowsocksUser(nil), h.users...), users...))
}
func (h *MultiInbound) DelUsers(names []string) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	removed := make(map[string]bool, len(names))
	for _, name := range names {
		removed[name] = true
	}
	users := make([]option.ShadowsocksUser, 0, len(h.users))
	for _, user := range h.users {
		if !removed[user.Name] {
			users = append(users, user)
		}
	}
	return h.setUsersLocked(users)
}
