package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DockerUserIdentityBinds supplies NSS metadata for numeric users that need
// not exist in the image. No host user database or credentials are mounted.
func DockerUserIdentityBinds(root, user string) ([]string, error) {
	uidText, gidText, _ := strings.Cut(user, ":")
	uid, err := strconv.ParseUint(uidText, 10, 32)
	if err != nil {
		return nil, nil // Named users must already exist in the selected image.
	}
	if gidText == "" {
		return nil, fmt.Errorf("sandbox: numeric Docker users must specify UID:GID to preserve the intended primary group")
	}
	gid, err := strconv.ParseUint(gidText, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("sandbox: a numeric Docker user requires a numeric group id")
	}
	passwd := fmt.Sprintf("agent:x:%d:%d::%s:/bin/bash\n", uid, gid, HomePath)
	if uid != 0 {
		passwd = "root:x:0:0:root:/root:/bin/bash\n" + passwd
	}
	group := fmt.Sprintf("agent:x:%d:\n", gid)
	if gid != 0 {
		group = "root:x:0:\n" + group
	}
	var binds []string
	for _, entry := range []struct{ name, data string }{{"passwd", passwd}, {"group", group}} {
		path := filepath.Join(root, "docker-"+entry.name)
		if err := os.WriteFile(path, []byte(entry.data), 0644); err != nil {
			return nil, err
		}
		binds = append(binds, DockerBind(path, "/etc/"+entry.name, "ro"))
	}
	return binds, nil
}
