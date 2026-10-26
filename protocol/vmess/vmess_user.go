package vmess

import (
	"github.com/sagernet/sing-box/common/dynamicuser"
	"github.com/sagernet/sing-box/option"
	"strconv"
)

func (h *Inbound) setUsers(users []option.VMessUser) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	return h.setUsersLocked(users)
}
func (h *Inbound) setUsersLocked(users []option.VMessUser) error {
	identities := make([]dynamicuser.User, 0, len(users))
	var uuids []string
	var alters []int
	for _, user := range users {
		identities = append(identities, dynamicuser.User{Name: user.Name, Secret: user.UUID + "\x00" + strconv.Itoa(user.AlterId)})
		uuids = append(uuids, user.UUID)
		alters = append(alters, user.AlterId)
	}
	err := h.usersState.Update(identities, func() error { return h.service.UpdateUsers(identities, uuids, alters) })
	if err == nil {
		h.users = append([]option.VMessUser(nil), users...)
	}
	return err
}
func (h *Inbound) AddUsers(users []option.VMessUser) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	return h.setUsersLocked(append(append([]option.VMessUser(nil), h.users...), users...))
}
func (h *Inbound) DelUsers(names []string) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	removed := make(map[string]bool, len(names))
	for _, name := range names {
		removed[name] = true
	}
	users := make([]option.VMessUser, 0, len(h.users))
	for _, user := range h.users {
		if !removed[user.Name] {
			users = append(users, user)
		}
	}
	return h.setUsersLocked(users)
}
