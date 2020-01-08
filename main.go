package main

import (
	"fmt"
	"os/exec"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func main() {

	c := &nftables.Conn{}

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	chain := c.AddChain(&nftables.Chain{
		Name:     "nfpoc",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityFilter,
	})

	set := &nftables.Set{
		Anonymous: true,
		Constant:  true,
		Table:     table,
		KeyType:   nftables.TypeInetService,
	}

	if err := c.AddSet(set, []nftables.SetElement{
		{Key: binaryutil.BigEndian.PutUint16(69)},
		{Key: binaryutil.BigEndian.PutUint16(1163)},
	}); err != nil {
		fmt.Printf("c.AddSet() failed: %s", err.Error())
	}

	r := c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},

			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			// [ lookup reg 1 set __set%d ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        set.Name,
				SetID:          set.ID,
			},
			// [ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	fmt.Printf("Before flush rule Handle is %d\n", r.Handle)

	if err := c.Flush(); err != nil {
		fmt.Printf(err.Error())
	}

	fmt.Printf("After flush rule Handle is %d\n", r.Handle)

	out, err := exec.Command("/usr/sbin/nft", "-a", "list", "table", "filter").Output()
	if err != nil {
		fmt.Printf(err.Error())
	}
	fmt.Printf("%s\n", out)
}
