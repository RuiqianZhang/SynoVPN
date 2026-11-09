package auth

import (
	"bufio"
	"context"
	"os"
	"os/user"
	"strconv"
	"strings"
)

type UserDirectory interface {
	Users(context.Context) ([]User, error)
}

func (a DSM) Users(ctx context.Context) ([]User, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []User{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 4 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || uid < 1024 || uid >= 65534 {
			continue
		}
		u, err := user.Lookup(fields[0])
		if err != nil {
			continue
		}
		gids, err := u.GroupIds()
		if err != nil {
			continue
		}
		gids = append(gids, u.Gid)
		allowed := false
		for _, group := range a.Groups {
			if inGroup(gids, group, user.LookupGroup) {
				allowed = true
				break
			}
		}
		if allowed {
			out = append(out, User{ID: "dsm:" + u.Uid + ":" + u.Username, Name: u.Username})
		}
	}
	return out, scanner.Err()
}
func (Demo) Users(context.Context) ([]User, error) {
	return []User{{ID: "demo:1000", Name: "演示用户", Admin: true}}, nil
}
