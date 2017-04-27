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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("EBTables Operations", func() {
	const (
		testChain   = "test"
		filterTable = "filter"
	)

	It("Adds a new EBTables chain", func() {
		ebt, err := New()
		Expect(err).NotTo(HaveOccurred())
		err = ebt.NewChain(filterTable, testChain)
		Expect(err).NotTo(HaveOccurred())
		_, err = ebt.List(filterTable, testChain)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Appends a rule", func() {
		mac := "4e:4f:41:48:00:00"
		ip := "10.1.1.1"
		common_args := []string{"-p", "IPv4", "-s", mac, "-o", "veth+", "--ip-src"}
		ebt, err := New()
		err = ebt.AppendUnique(filterTable, testChain, append(common_args, ip, "-j", "ACCEPT")...)
		Expect(err).NotTo(HaveOccurred())
		rules, err := ebt.List(filterTable, testChain)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(rules)).To(Equal(1))
	})

	It("Does not append an existing rule", func() {
		mac := "4e:4f:41:48:00:00"
		ip := "10.1.1.1"
		common_args := []string{"-p", "IPv4", "-s", mac, "-o", "veth+", "--ip-src"}
		ebt, err := New()
		err = ebt.AppendUnique(filterTable, testChain, append(common_args, ip, "-j", "ACCEPT")...)
		Expect(err).NotTo(HaveOccurred())
		rules, err := ebt.List(filterTable, testChain)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(rules)).To(Equal(1))
	})

	It("Inserts a rule.", func() {
		mac := "4e:4f:41:48:00:00"
		ip := "10.1.1.2"
		common_args := []string{"-p", "IPv4", "-s", mac, "-o", "veth+", "--ip-src"}
		ebt, err := New()
		err = ebt.Insert(filterTable, testChain, 1, append(common_args, ip, "-j", "ACCEPT")...)
		Expect(err).NotTo(HaveOccurred())
		rules, err := ebt.List(filterTable, testChain)
		Expect(err).NotTo(HaveOccurred())
		// Make sure its the first rule.
		Expect(rules[0]).To(Equal("-p IPv4 -s 4e:4f:41:48:00:00 -o veth+ --ip-src 10.1.1.2 -j ACCEPT"))
		Expect(len(rules)).To(Equal(2))
	})

	It("Deletes a rule", func() {
		mac := "4e:4f:41:48:00:00"
		ip := "10.1.1.1"
		common_args := []string{"-p", "IPv4", "-s", mac, "-o", "veth+", "--ip-src"}
		ebt, err := New()
		err = ebt.Delete(filterTable, testChain, append(common_args, ip, "-j", "ACCEPT")...)
		Expect(err).NotTo(HaveOccurred())
		rules, err := ebt.List(filterTable, testChain)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(rules)).To(Equal(1))
	})

	It("Deletes a chain", func() {
		ebt, err := New()
		Expect(err).NotTo(HaveOccurred())
		err = ebt.DeleteChain(filterTable, testChain)
		Expect(err).NotTo(HaveOccurred())
		_, err = ebt.List(filterTable, testChain)
		Expect(err).To(HaveOccurred())
	})
})
