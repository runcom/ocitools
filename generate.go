package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
	seccomp "github.com/opencontainers/ocitools/seccomp-gen"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/syndtr/gocapability/capability"
	"github.com/urfave/cli"
)

var generateFlags = []cli.Flag{
	cli.StringFlag{Name: "output", Value: "output", Usage: "output file (defaults to stdout)"},
	cli.StringFlag{Name: "rootfs", Value: "rootfs", Usage: "path to the rootfs"},
	cli.BoolFlag{Name: "read-only", Usage: "make the container's rootfs read-only"},
	cli.BoolFlag{Name: "privileged", Usage: "enabled privileged container settings"},
	cli.BoolFlag{Name: "no-new-privileges", Usage: "set no new privileges bit for the container process"},
	cli.BoolFlag{Name: "tty", Usage: "allocate a new tty for the container process"},
	cli.StringFlag{Name: "hostname", Usage: "hostname value for the container"},
	cli.IntFlag{Name: "uid", Usage: "uid for the process"},
	cli.IntFlag{Name: "gid", Usage: "gid for the process"},
	cli.StringSliceFlag{Name: "groups", Usage: "supplementary groups for the process"},
	cli.StringSliceFlag{Name: "cap-add", Usage: "add capabilities"},
	cli.StringSliceFlag{Name: "cap-drop", Usage: "drop capabilities"},
	cli.StringFlag{Name: "cgroup", Usage: "cgroup namespace"},
	cli.StringFlag{Name: "network", Usage: "network namespace"},
	cli.StringFlag{Name: "mount", Usage: "mount namespace"},
	cli.StringFlag{Name: "pid", Usage: "pid namespace"},
	cli.StringFlag{Name: "ipc", Usage: "ipc namespace"},
	cli.StringFlag{Name: "user", Usage: "user namespace"},
	cli.StringFlag{Name: "uts", Usage: "uts namespace"},
	cli.StringFlag{Name: "selinux-label", Usage: "process selinux label"},
	cli.StringFlag{Name: "mount-label", Usage: "selinux mount context label"},
	cli.StringSliceFlag{Name: "tmpfs", Usage: "mount tmpfs"},
	cli.StringSliceFlag{Name: "args", Usage: "command to run in the container"},
	cli.StringSliceFlag{Name: "env", Usage: "add environment variable"},
	cli.StringFlag{Name: "cgroups-path", Usage: "specify the path to the cgroups"},
	cli.StringFlag{Name: "mount-cgroups", Value: "no", Usage: "mount cgroups (rw,ro,no)"},
	cli.StringSliceFlag{Name: "bind", Usage: "bind mount directories src:dest:(rw,ro)"},
	cli.StringSliceFlag{Name: "prestart", Usage: "path to prestart hooks"},
	cli.StringSliceFlag{Name: "poststart", Usage: "path to poststart hooks"},
	cli.StringSliceFlag{Name: "poststop", Usage: "path to poststop hooks"},
	cli.StringFlag{Name: "root-propagation", Usage: "mount propagation for root"},
	cli.StringFlag{Name: "os", Value: runtime.GOOS, Usage: "operating system the container is created for"},
	cli.StringFlag{Name: "arch", Value: runtime.GOARCH, Usage: "architecture the container is created for"},
	cli.StringFlag{Name: "cwd", Value: "/", Usage: "current working directory for the process"},
	cli.StringSliceFlag{Name: "uidmappings", Usage: "add UIDMappings e.g HostID:ContainerID:Size"},
	cli.StringSliceFlag{Name: "gidmappings", Usage: "add GIDMappings e.g HostID:ContainerID:Size"},
	cli.StringSliceFlag{Name: "sysctl", Usage: "add sysctl settings e.g net.ipv4.forward=1"},
	cli.StringFlag{Name: "apparmor", Usage: "specifies the the apparmor profile for the container"},
	cli.BoolFlag{Name: "seccomp-only", Usage: "specifies to export just a seccomp configuration file"},
	cli.StringFlag{Name: "seccomp-default", Usage: "specifies the the defaultaction of Seccomp syscall restrictions"},
	cli.StringFlag{Name: "seccomp-arch", Usage: "specifies Additional architectures permitted to be used for system calls"},
	cli.StringFlag{Name: "seccomp-allow", Usage: "specifies syscalls to be added to allowed"},
	cli.StringFlag{Name: "seccomp-trap", Usage: "specifies syscalls to be added to list that returns an error"},
	cli.StringFlag{Name: "seccomp-errno", Usage: "specifies syscalls to be added to list that returns an error"},
	cli.StringFlag{Name: "seccomp-trace", Usage: "specifies syscalls to be added to list that returns an error"},
	cli.StringFlag{Name: "seccomp-kill", Usage: "specifies syscalls to be added to list that returns an error"},
	cli.StringFlag{Name: "template", Usage: "base template to use for creating the configuration"},
	cli.StringSliceFlag{Name: "label", Usage: "add annotations to the configuration e.g. key=value"},
}

var (
	defaultCaps = []string{
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE",
		"CAP_FSETID",
		"CAP_FOWNER",
		"CAP_MKNOD",
		"CAP_NET_RAW",
		"CAP_SETGID",
		"CAP_SETUID",
		"CAP_SETFCAP",
		"CAP_SETPCAP",
		"CAP_NET_BIND_SERVICE",
		"CAP_SYS_CHROOT",
		"CAP_KILL",
		"CAP_AUDIT_WRITE",
	}
)

var generateCommand = cli.Command{
	Name:   "generate",
	Usage:  "generate a OCI spec file",
	Flags:  generateFlags,
	Before: before,
	Action: func(context *cli.Context) error {
		spec := getDefaultTemplate()
		template := context.String("template")
		if template != "" {
			var err error
			spec, err = loadTemplate(template)
			if err != nil {
				return err
			}
		}

		err := modify(spec, context)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(&spec, "", "\t")
		if err != nil {
			return err
		}
		if !onlyExportFlagSpecified(context) {
			if context.IsSet("output") {
				output := context.String("output")
				if err := ioutil.WriteFile(output, data, 0666); err != nil {
					return err
				}
			} else {
				_, err = os.Stdout.Write(data)
				if err != nil {
					return err
				}
			}
		}
		return nil
	},
}

func onlyExportFlagSpecified(context *cli.Context) bool {
	onlyExportFlags := []bool{
		context.Bool("seccomp-only"),
	}
	for _, flag := range onlyExportFlags {
		if flag {
			return true
		}
	}
	return false
}

func loadTemplate(path string) (spec *rspec.Spec, err error) {
	cf, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("template configuration at %s not found", path)
		}
	}
	defer cf.Close()

	if err = json.NewDecoder(cf).Decode(&spec); err != nil {
		return
	}
	return spec, nil
}

func modify(spec *rspec.Spec, context *cli.Context) error {
	if len(spec.Version) == 0 {
		spec.Version = rspec.Version
	}
	spec.Root.Path = context.String("rootfs")
	if context.IsSet("read-only") {
		spec.Root.Readonly = context.Bool("read-only")
	}
	spec.Hostname = context.String("hostname")
	spec.Process.User.UID = uint32(context.Int("uid"))
	spec.Process.User.GID = uint32(context.Int("gid"))
	if spec.Process.Args == nil {
		spec.Process.Args = make([]string, 0)
	}
	spec.Process.SelinuxLabel = context.String("selinux-label")
	spec.Linux.CgroupsPath = sPtr(context.String("cgroups-path"))
	spec.Linux.MountLabel = context.String("mount-label")
	spec.Platform.OS = context.String("os")
	spec.Platform.Arch = context.String("arch")
	spec.Process.Cwd = context.String("cwd")
	spec.Process.ApparmorProfile = context.String("apparmor")
	if context.IsSet("no-new-privileges") {
		spec.Process.NoNewPrivileges = context.Bool("no-new-privileges")
	}
	if context.IsSet("tty") {
		spec.Process.Terminal = context.Bool("tty")
	}

	for i, a := range context.StringSlice("args") {
		if a != "" {
			if i == 0 {
				// Replace "sh" from getDefaultTemplate()
				spec.Process.Args[0] = a
			} else {
				spec.Process.Args = append(spec.Process.Args, a)
			}
		}
	}

	for _, e := range context.StringSlice("env") {
		spec.Process.Env = append(spec.Process.Env, e)
	}

	groups := context.StringSlice("groups")
	if groups != nil {
		for _, g := range groups {
			groupID, err := strconv.Atoi(g)
			if err != nil {
				return err
			}
			spec.Process.User.AdditionalGids = append(spec.Process.User.AdditionalGids, uint32(groupID))
		}
	}

	spec.Linux.Sysctl = make(map[string]string)
	sysctls := context.StringSlice("sysctl")
	for _, s := range sysctls {
		pair := strings.Split(s, "=")
		if len(pair) != 2 {
			return fmt.Errorf("incorrectly specified sysctl: %s", s)
		}
		spec.Linux.Sysctl[pair[0]] = pair[1]
	}

	spec.Annotations = make(map[string]string)
	labels := context.StringSlice("label")
	for _, l := range labels {
		pair := strings.Split(l, "=")
		if len(pair) != 2 {
			return fmt.Errorf("incorrectly specified label: %s", l)
		}
		spec.Annotations[pair[0]] = pair[1]
	}

	if err := setupCapabilities(spec, context); err != nil {
		return err
	}

	setupNamespaces(spec, context)
	if err := addTmpfsMounts(spec, context); err != nil {
		return err
	}
	if err := mountCgroups(spec, context); err != nil {
		return err
	}
	if err := addBindMounts(spec, context); err != nil {
		return err
	}
	if err := addHooks(spec, context); err != nil {
		return err
	}
	if err := addRootPropagation(spec, context); err != nil {
		return err
	}
	if err := addIDMappings(spec, context); err != nil {
		return err
	}
	if err := addSeccomp(spec, context); err != nil {
		return err
	}

	return nil
}

func addSeccomp(spec *rspec.Spec, context *cli.Context) error {
	var secc rspec.Seccomp

	seccompDefault := context.String("seccomp-default")
	seccompArch := context.String("seccomp-arch")
	seccompKill := context.String("seccomp-kill")
	seccompTrace := context.String("seccomp-trace")
	seccompErrno := context.String("seccomp-errno")
	seccompTrap := context.String("seccomp-trap")
	seccompAllow := context.String("seccomp-allow")

	// Set the DefaultAction of seccomp
	if seccompDefault == "" {
		seccompDefault = "allow"
	}
	err := seccomp.ParseDefaultAction(seccompDefault, &secc)
	if err != nil {
		return err
	}

	// Add the additional architectures permitted to be used for system calls
	if seccompArch == "" {
		seccompArch = "amd64,x86,x32"
	}
	err = seccomp.ParseArchitectureFlag(seccompArch, &secc)
	if err != nil {
		return err
	}

	err = seccomp.ParseSyscallFlag("kill", seccompKill, &secc)
	if err != nil {
		return err
	}

	err = seccomp.ParseSyscallFlag("trace", seccompTrace, &secc)
	if err != nil {
		return err
	}

	err = seccomp.ParseSyscallFlag("errno", seccompErrno, &secc)
	if err != nil {
		return err
	}

	err = seccomp.ParseSyscallFlag("trap", seccompTrap, &secc)
	if err != nil {
		return err
	}

	err = seccomp.ParseSyscallFlag("allow", seccompAllow, &secc)
	if err != nil {
		return err
	}
	if context.Bool("seccomp-only") {
		data, err := json.MarshalIndent(&secc, "", "\t")
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile("config.seccomp", data, 0666); err != nil {
			return err
		}
		return nil
	}

	spec.Linux.Seccomp = &secc
	return nil
}

func addIDMappings(spec *rspec.Spec, context *cli.Context) error {
	for _, uidms := range context.StringSlice("uidmappings") {
		idm := strings.Split(uidms, ":")
		if len(idm) == 3 {
			hid, err := strconv.Atoi(idm[0])
			cid, err := strconv.Atoi(idm[1])
			size, err := strconv.Atoi(idm[2])
			if err != nil {
				return err
			}
			uidmapping := rspec.IDMapping{
				HostID:      uint32(hid),
				ContainerID: uint32(cid),
				Size:        uint32(size),
			}
			spec.Linux.UIDMappings = append(spec.Linux.UIDMappings, uidmapping)
		} else {
			return fmt.Errorf("uidmappings error: %s", uidms)
		}
	}

	for _, gidms := range context.StringSlice("gidmappings") {
		idm := strings.Split(gidms, ":")
		if len(idm) == 3 {
			hid, err := strconv.Atoi(idm[0])
			cid, err := strconv.Atoi(idm[1])
			size, err := strconv.Atoi(idm[2])
			if err != nil {
				return err
			}
			gidmapping := rspec.IDMapping{
				HostID:      uint32(hid),
				ContainerID: uint32(cid),
				Size:        uint32(size),
			}
			spec.Linux.GIDMappings = append(spec.Linux.GIDMappings, gidmapping)
		} else {
			return fmt.Errorf("gidmappings error: %s", gidms)
		}
	}

	return nil
}

func addRootPropagation(spec *rspec.Spec, context *cli.Context) error {
	rp := context.String("root-propagation")
	switch rp {
	case "":
	case "private":
	case "rprivate":
	case "slave":
	case "rslave":
	case "shared":
	case "rshared":
	default:
		return fmt.Errorf("rootfs-propagation must be empty or one of private|rprivate|slave|rslave|shared|rshared")
	}
	spec.Linux.RootfsPropagation = rp
	return nil
}

func addHooks(spec *rspec.Spec, context *cli.Context) error {
	for _, pre := range context.StringSlice("prestart") {
		parts := strings.Split(pre, ":")
		args := []string{}
		path := parts[0]
		if len(parts) > 1 {
			args = parts[1:]
		}
		spec.Hooks.Prestart = append(spec.Hooks.Prestart, rspec.Hook{Path: path, Args: args})
	}
	for _, post := range context.StringSlice("poststop") {
		parts := strings.Split(post, ":")
		args := []string{}
		path := parts[0]
		if len(parts) > 1 {
			args = parts[1:]
		}
		spec.Hooks.Poststop = append(spec.Hooks.Poststop, rspec.Hook{Path: path, Args: args})
	}
	for _, poststart := range context.StringSlice("poststart") {
		parts := strings.Split(poststart, ":")
		args := []string{}
		path := parts[0]
		if len(parts) > 1 {
			args = parts[1:]
		}
		spec.Hooks.Poststart = append(spec.Hooks.Poststart, rspec.Hook{Path: path, Args: args})
	}
	return nil
}

func addTmpfsMounts(spec *rspec.Spec, context *cli.Context) error {
	for _, dest := range context.StringSlice("tmpfs") {
		mnt := rspec.Mount{
			Destination: dest,
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     []string{"nosuid", "nodev", "mode=755"},
		}
		spec.Mounts = append(spec.Mounts, mnt)
	}
	return nil
}

func mountCgroups(spec *rspec.Spec, context *cli.Context) error {
	mountCgroupOption := context.String("mount-cgroups")
	switch mountCgroupOption {
	case "ro":
	case "rw":
	case "no":
		return nil
	default:
		return fmt.Errorf("--mount-cgroups should be one of (ro,rw,no)")
	}

	mnt := rspec.Mount{
		Destination: "/sys/fs/cgroup",
		Type:        "cgroup",
		Source:      "cgroup",
		Options:     []string{"nosuid", "noexec", "nodev", "relatime", mountCgroupOption},
	}
	spec.Mounts = append(spec.Mounts, mnt)

	return nil
}

func addBindMounts(spec *rspec.Spec, context *cli.Context) error {
	for _, b := range context.StringSlice("bind") {
		var source, dest string
		options := "ro"
		bparts := strings.SplitN(b, ":", 3)
		switch len(bparts) {
		case 2:
			source, dest = bparts[0], bparts[1]
		case 3:
			source, dest, options = bparts[0], bparts[1], bparts[2]
		default:
			return fmt.Errorf("--bind should have format src:dest:[options]")
		}
		defaultOptions := []string{"bind"}
		mnt := rspec.Mount{
			Destination: dest,
			Type:        "bind",
			Source:      source,
			Options:     append(defaultOptions, options),
		}
		spec.Mounts = append(spec.Mounts, mnt)
	}
	return nil
}

func setupCapabilities(spec *rspec.Spec, context *cli.Context) error {
	var finalCapList []string

	// Add all capabilities in privileged mode.
	privileged := false
	if context.IsSet("privileged") {
		privileged = context.Bool("privileged")
	}
	if privileged {
		for _, cap := range capability.List() {
			finalCapList = append(finalCapList, fmt.Sprintf("CAP_%s", strings.ToUpper(cap.String())))
		}
		spec.Process.Capabilities = finalCapList
		spec.Process.SelinuxLabel = ""
		spec.Process.ApparmorProfile = ""
		spec.Linux.Seccomp = nil
		return nil
	}

	capMappings := make(map[string]bool)
	for _, cap := range capability.List() {
		key := strings.ToUpper(cap.String())
		capMappings[key] = true
	}

	defaultCaps := spec.Process.Capabilities

	addedCapsMap := make(map[string]bool)
	for _, cap := range defaultCaps {
		addedCapsMap[cap] = true
	}

	addCapList := make([]string, len(defaultCaps))
	copy(addCapList, defaultCaps)
	addCaps := context.StringSlice("cap-add")
	for _, c := range addCaps {
		if !capMappings[c] {
			return fmt.Errorf("Invalid value passed for adding capability")
		}
		cp := fmt.Sprintf("CAP_%s", c)
		if !addedCapsMap[cp] {
			addCapList = append(addCapList, cp)
			addedCapsMap[cp] = true
		}
	}
	dropCaps := context.StringSlice("cap-drop")
	dropCapsMap := make(map[string]bool)
	for _, c := range dropCaps {
		if !capMappings[c] {
			return fmt.Errorf("Invalid value passed for dropping capability")
		}
		cp := fmt.Sprintf("CAP_%s", c)
		dropCapsMap[cp] = true
	}

	for _, c := range addCapList {
		if !dropCapsMap[c] {
			finalCapList = append(finalCapList, c)
		}
	}
	spec.Process.Capabilities = finalCapList
	return nil
}

func mapStrToNamespace(ns string, path string) rspec.Namespace {
	switch ns {
	case "network":
		return rspec.Namespace{Type: rspec.NetworkNamespace, Path: path}
	case "pid":
		return rspec.Namespace{Type: rspec.PIDNamespace, Path: path}
	case "mount":
		return rspec.Namespace{Type: rspec.MountNamespace, Path: path}
	case "ipc":
		return rspec.Namespace{Type: rspec.IPCNamespace, Path: path}
	case "uts":
		return rspec.Namespace{Type: rspec.UTSNamespace, Path: path}
	case "user":
		return rspec.Namespace{Type: rspec.UserNamespace, Path: path}
	case "cgroup":
		return rspec.Namespace{Type: rspec.CgroupNamespace, Path: path}
	default:
		logrus.Fatalf("Should not reach here!")
	}
	return rspec.Namespace{}
}

func setupNamespaces(spec *rspec.Spec, context *cli.Context) {
	var needsNewUser = false
	if len(context.StringSlice("uidmappings")) > 0 || len(context.StringSlice("gidmappings")) > 0 {
		needsNewUser = true
	}

	namespaces := []string{"network", "pid", "mount", "ipc", "uts", "user", "cgroup"}
	for _, nsName := range namespaces {
		if !context.IsSet(nsName) && !(needsNewUser && nsName == "user") {
			continue
		}
		nsPath := context.String(nsName)
		if nsPath == "host" {
			ns := mapStrToNamespace(nsName, "")
			removeNamespace(&spec.Linux.Namespaces, ns.Type)
			continue
		}
		ns := mapStrToNamespace(nsName, nsPath)
		replaceOrAppendNamespace(&spec.Linux.Namespaces, ns)
	}
}

func replaceOrAppendNamespace(namespaces *[]rspec.Namespace, namespace rspec.Namespace) {
	for i, ns := range *namespaces {
		if ns.Type == namespace.Type {
			(*namespaces)[i] = namespace
			return
		}
	}
	new := append(*namespaces, namespace)
	*namespaces = new
}

func removeNamespace(namespaces *[]rspec.Namespace, namespaceType rspec.NamespaceType) {
	for i, ns := range *namespaces {
		if ns.Type == namespaceType {
			*namespaces = append((*namespaces)[:i], (*namespaces)[i+1:]...)
			return
		}
	}
}

func sPtr(s string) *string { return &s }

func getDefaultTemplate() *rspec.Spec {
	spec := rspec.Spec{
		Version: rspec.Version,
		Platform: rspec.Platform{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
		Root: rspec.Root{
			Path:     "",
			Readonly: false,
		},
		Process: rspec.Process{
			Terminal: false,
			User:     rspec.User{},
			Args: []string{
				"sh",
			},
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"TERM=xterm",
			},
			Cwd: "/",
			Capabilities: []string{
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_FSETID",
				"CAP_FOWNER",
				"CAP_MKNOD",
				"CAP_NET_RAW",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETFCAP",
				"CAP_SETPCAP",
				"CAP_NET_BIND_SERVICE",
				"CAP_SYS_CHROOT",
				"CAP_KILL",
				"CAP_AUDIT_WRITE",
			},
			Rlimits: []rspec.Rlimit{
				{
					Type: "RLIMIT_NOFILE",
					Hard: uint64(1024),
					Soft: uint64(1024),
				},
			},
		},
		Hostname: "shell",
		Mounts: []rspec.Mount{
			{
				Destination: "/proc",
				Type:        "proc",
				Source:      "proc",
				Options:     nil,
			},
			{
				Destination: "/dev",
				Type:        "tmpfs",
				Source:      "tmpfs",
				Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
			},
			{
				Destination: "/dev/pts",
				Type:        "devpts",
				Source:      "devpts",
				Options:     []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"},
			},
			{
				Destination: "/dev/shm",
				Type:        "tmpfs",
				Source:      "shm",
				Options:     []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"},
			},
			{
				Destination: "/dev/mqueue",
				Type:        "mqueue",
				Source:      "mqueue",
				Options:     []string{"nosuid", "noexec", "nodev"},
			},
			{
				Destination: "/sys",
				Type:        "sysfs",
				Source:      "sysfs",
				Options:     []string{"nosuid", "noexec", "nodev", "ro"},
			},
		},
		Linux: rspec.Linux{
			Resources: &rspec.Resources{
				Devices: []rspec.DeviceCgroup{
					{
						Allow:  false,
						Access: sPtr("rwm"),
					},
				},
			},
			Namespaces: []rspec.Namespace{
				{
					Type: "pid",
				},
				{
					Type: "network",
				},
				{
					Type: "ipc",
				},
				{
					Type: "uts",
				},
				{
					Type: "mount",
				},
			},
			Devices: []rspec.Device{},
		},
	}

	return &spec
}
