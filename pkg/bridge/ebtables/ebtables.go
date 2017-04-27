// Copyright 2017 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebtables

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/containernetworking/cni/pkg/utils/sysctl"
)

const (
	sysctlBridgeCallIPTables = "net/bridge/bridge-nf-call-iptables"
)

type Error struct {
	exec.ExitError
	msg string
}

func (e *Error) ExitStatus() int {
	return e.Sys().(syscall.WaitStatus).ExitStatus()
}

func (e *Error) Error() string {
	return fmt.Sprintf("exit status %v: %v", e.ExitStatus(), e.msg)
}

type EBTables struct {
	path string
}

func New() (*EBTables, error) {
	path, err := exec.LookPath("ebtables")
	if err != nil {
		return nil, err
	}

	modprobe, err := exec.LookPath("modprobe")
	if err != nil {
		return nil, err
	}

	var _, stderr bytes.Buffer
	args := []string{modprobe, "br-netfilter"}
	cmd := exec.Cmd{
		Path:   modprobe,
		Args:   args,
		Stdout: nil,
		Stderr: &stderr,
	}

	if err := cmd.Run(); err != nil {
		return nil, &Error{*(err.(*exec.ExitError)), stderr.String()}
	}

	// Allow iptables to see bridged traffic.
	if _, err := sysctl.Sysctl(sysctlBridgeCallIPTables, "1"); err != nil {
		return nil, err
	}

	ebt := EBTables{
		path: path,
	}

	return &ebt, nil
}

// List lists the current rules in the specified chain and table.
func (ebt *EBTables) List(table, chain string) ([]string, error) {
	cmd := []string{"-t", table, "-L", chain, "--Lmac2"}
	var stdout bytes.Buffer
	if err := ebt.runWithOutput(cmd, &stdout); err != nil {
		return nil, err
	}
	var rules []string
	for _, r := range strings.Split(stdout.String(), "\n") {
		// Skip blank lines and lines like "Bridge table: filter"
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, "Bridge") || r == "" {
			continue
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// Exists returns true if the rule specified matches an existing rule in the
// specified chain and table.
func (ebt *EBTables) Exists(table, chain string, rule ...string) (bool, error) {
	rules, err := ebt.List(table, chain)
	if err != nil {
		return false, err
	}
	for _, r := range rules {
		if r == strings.Join(rule, " ") {
			return true, nil
		}
	}

	return false, nil
}

// Insert inserts a rule into the specified table and chain at the specified
// position.
func (ebt *EBTables) Insert(table, chain string, pos int, rule ...string) error {
	cmd := append([]string{"-t", table, "-I", chain, strconv.Itoa(pos)}, rule...)
	return ebt.run(cmd...)
}

// Append appends a rule to the specified chain and table.
func (ebt *EBTables) Append(table, chain string, rule ...string) error {
	cmd := append([]string{"-t", table, "-A", chain}, rule...)
	return ebt.run(cmd...)
}

// AppendUnique appends a rule only if the rule does not exist.
func (ebt *EBTables) AppendUnique(table, chain string, rule ...string) error {
	exists, err := ebt.Exists(table, chain, rule...)
	if err != nil {
		return err
	}

	if !exists {
		return ebt.Append(table, chain, rule...)
	}
	return nil
}

// Delete removes a rule from the specified chain and table.
func (ebt *EBTables) Delete(table, chain string, rule ...string) error {
	cmd := append([]string{"-t", table, "-D", chain}, rule...)
	return ebt.run(cmd...)
}

// NewChain creates a new ebtables chain.
func (ebt *EBTables) NewChain(table, chain string) error {
	return ebt.run("-t", table, "-N", chain)
}

// DeleteChain removes an ebtables chain.
func (ebt *EBTables) DeleteChain(table, chain string) error {
	return ebt.run("-t", table, "-X", chain)
}

func (ebt *EBTables) run(args ...string) error {
	return ebt.runWithOutput(args, nil)
}

func (ebt *EBTables) runWithOutput(args []string, stdout io.Writer) error {
	args = append([]string{ebt.path, "--concurrent"}, args...)
	var stderr bytes.Buffer
	cmd := exec.Cmd{
		Path:   ebt.path,
		Args:   args,
		Stdout: stdout,
		Stderr: &stderr,
	}
	if err := cmd.Run(); err != nil {
		return &Error{*(err.(*exec.ExitError)), stderr.String()}
	}
	return nil
}
