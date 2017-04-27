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

package bridge

import (
	"strings"

	"github.com/containernetworking/cni/pkg/bridge/ebtables"
)

const (
	dedupChain  = "CNI-DEDUP"
	filterTable = "filter"
	outputChain = "OUTPUT"
)

func AddDedupRules(mac, ip, nw string) error {
	ebt, err := ebtables.New()
	if err != nil {
		return err
	}
	if err := ebt.NewChain(filterTable, dedupChain); err != nil {
		// Make chain creation idempotent.
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}

	common_args := []string{"-p", "IPv4", "-s", mac, "-o", "veth+", "--ip-src"}

	if err := ebt.AppendUnique(filterTable, dedupChain, append(common_args, ip, "-j", "ACCEPT")...); err != nil {
		return err
	}
	if err := ebt.AppendUnique(filterTable, dedupChain, append(common_args, nw, "-j", "DROP")...); err != nil {
		return err
	}

	if err := ebt.AppendUnique(filterTable, outputChain, "-j", dedupChain); err != nil {
		return err
	}

	return nil

}

func DeleteDedupRules() error {
	ebt, err := ebtables.New()
	if err != nil {
		return err
	}
	if err := ebt.Delete(filterTable, outputChain, "-j", dedupChain); err != nil {
		// Make rule deletion idempotent.
		if strings.Contains(err.Error(), "Illegal target name") {
			return nil
		}
		return err
	}
	if err := ebt.DeleteChain(filterTable, dedupChain); err != nil {
		// Make chain deletion idempotent.
		if strings.Contains(err.Error(), "Illegal target name") {
			return nil
		}
		return err
	}

	return nil
}
