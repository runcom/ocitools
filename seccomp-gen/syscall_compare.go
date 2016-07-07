package seccompgen

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	types "github.com/opencontainers/runtime-spec/specs-go"
)

/*******************************************************
This file is a bunch of helper functions for determining
what action should be taken for new syscalls.
See github.com/grantseltzer/manhattan/Resources/Logic.png
for a flowchart and explanation
********************************************************/

func decideCourseOfAction(newSyscall *types.Syscall, syscalls []types.Syscall) (string, error) {
	ruleForSyscallAlreadyExists := false

	var sliceOfDeterminedActions []string
	for i, syscall := range syscalls {
		if syscall.Name == newSyscall.Name {
			ruleForSyscallAlreadyExists = true

			if identical(newSyscall, &syscall) {
				sliceOfDeterminedActions = append(sliceOfDeterminedActions, nothing)
			}

			if sameAction(newSyscall, &syscall) {
				if bothHaveArgs(newSyscall, &syscall) {
					sliceOfDeterminedActions = append(sliceOfDeterminedActions, appnd)
				}
				if onlyOneHasArgs(newSyscall, &syscall) {
					if firstParamOnlyHasArgs(newSyscall, &syscall) {
						sliceOfDeterminedActions = append(sliceOfDeterminedActions, "overwrite:"+strconv.Itoa(i))
					} else {
						sliceOfDeterminedActions = append(sliceOfDeterminedActions, nothing)
					}
				}
			}

			if !sameAction(newSyscall, &syscall) {
				if bothHaveArgs(newSyscall, &syscall) {
					if sameArgs(newSyscall, &syscall) {
						sliceOfDeterminedActions = append(sliceOfDeterminedActions, "overwrite:"+strconv.Itoa(i))
					}
					if !sameArgs(newSyscall, &syscall) {
						sliceOfDeterminedActions = append(sliceOfDeterminedActions, appnd)
					}
				}
				if onlyOneHasArgs(newSyscall, &syscall) {
					sliceOfDeterminedActions = append(sliceOfDeterminedActions, appnd)
				}
				if neitherHasArgs(newSyscall, &syscall) {
					sliceOfDeterminedActions = append(sliceOfDeterminedActions, "overwrite:"+strconv.Itoa(i))
				}
			}
		}
	}

	if !ruleForSyscallAlreadyExists {
		sliceOfDeterminedActions = append(sliceOfDeterminedActions, appnd)
	}

	// Nothing has highest priority
	for _, determinedAction := range sliceOfDeterminedActions {
		if determinedAction == nothing {
			return determinedAction, nil
		}
	}

	// Overwrite has second highest priority
	for _, determinedAction := range sliceOfDeterminedActions {
		if strings.Contains(determinedAction, overwrite) {
			return determinedAction, nil
		}
	}

	// Append has the lowest priority
	for _, determinedAction := range sliceOfDeterminedActions {
		if determinedAction == appnd {
			return determinedAction, nil
		}
	}

	return "error", fmt.Errorf("Trouble determining action: %s", sliceOfDeterminedActions)
}

func hasArguments(config *types.Syscall) bool {
	nilSyscall := new(types.Syscall)
	return !sameArgs(nilSyscall, config)
}

func identical(config1, config2 *types.Syscall) bool {
	return reflect.DeepEqual(config1, config2)
}

func identicalExceptAction(config1, config2 *types.Syscall) bool {
	samename := sameName(config1, config2)
	sameAction := sameAction(config1, config2)
	sameArgs := sameArgs(config1, config2)

	return samename && !sameAction && sameArgs
}

func identicalExceptArgs(config1, config2 *types.Syscall) bool {
	samename := sameName(config1, config2)
	sameAction := sameAction(config1, config2)
	sameArgs := sameArgs(config1, config2)

	return samename && sameAction && !sameArgs
}

func sameName(config1, config2 *types.Syscall) bool {
	return config1.Name == config2.Name
}

func sameAction(config1, config2 *types.Syscall) bool {
	return config1.Action == config2.Action
}

func sameArgs(config1, config2 *types.Syscall) bool {
	return reflect.DeepEqual(config1.Args, config2.Args)
}

func bothHaveArgs(config1, config2 *types.Syscall) bool {
	return hasArguments(config1) && hasArguments(config2)
}

func onlyOneHasArgs(config1, config2 *types.Syscall) bool {
	conf1 := hasArguments(config1)
	conf2 := hasArguments(config2)

	return (conf1 && !conf2) || (!conf1 && conf2)
}

func neitherHasArgs(config1, config2 *types.Syscall) bool {
	return !hasArguments(config1) && !hasArguments(config2)
}

func firstParamOnlyHasArgs(config1, config2 *types.Syscall) bool {
	return !hasArguments(config1) && hasArguments(config2)
}
