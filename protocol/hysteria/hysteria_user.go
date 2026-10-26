package hysteria

import (
	"github.com/sagernet/sing-box/common/dynamicuser"
	"github.com/sagernet/sing-box/option"
)

func (h *Inbound) setUsers(users []option.HysteriaUser) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	return h.setUsersLocked(users)
}
func (h *Inbound) setUsersLocked(users []option.HysteriaUser) error {
	identities := make([]dynamicuser.User, 0, len(users))
	var passwords []string
	for _, user := range users {
		identities = append(identities, dynamicuser.User{Name: user.Name, Secret: hysteriaPassword(user)})
		passwords = append(passwords, hysteriaPassword(user))
	}
	err := h.usersState.Update(identities, func() error { h.service.UpdateUsers(identities, passwords); return nil })
	if err == nil {
		h.users = append([]option.HysteriaUser(nil), users...)
	}
	return err
}
func (h *Inbound) AddUsers(users []option.HysteriaUser) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	return h.setUsersLocked(append(append([]option.HysteriaUser(nil), h.users...), users...))
}
func (h *Inbound) DelUsers(names []string) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	removed := make(map[string]bool, len(names))
	for _, name := range names {
		removed[name] = true
	}
	users := make([]option.HysteriaUser, 0, len(h.users))
	for _, user := range h.users {
		if !removed[user.Name] {
			users = append(users, user)
		}
	}
	return h.setUsersLocked(users)
}

func hysteriaPassword(user option.HysteriaUser) string {
	if user.AuthString != "" {
		return user.AuthString
	}
	return string(user.Auth)
}
