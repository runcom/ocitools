package ociseccompgen

import (
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
)

// DefaultFullPath returns the default full path/name for output configuration files
func DefaultFullPath() string {
	return (parseLocation(pwd(), parseNameWithNumber("manhattan", 0)))
}

func parseLocation(location, name string) string {
	return strings.TrimSuffix(location, "/") + "/" + name
}

func parseNameWithNumber(name string, number int) string {
	var fullName string
	if number == 0 {
		fullName = name + ".json"
	} else {
		fullName = name + strconv.Itoa(number) + ".json"
	}
	if _, err := os.Stat(pwd() + "/" + fullName); os.IsNotExist(err) {
		return fullName
	}
	return parseNameWithNumber(name, number+1)

}

func userHomeDir() string {
	usr, err := user.Current()
	if err != nil {
		logrus.Fatal("Could not obtain users home directory. Try setting a custom output location with -location")
	}
	return usr.HomeDir
}

func pwd() string {
	pwd, err := os.Getwd()
	if err != nil {
		logrus.Fatal("Could not get current working directory")
	}
	return pwd
}
