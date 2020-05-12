// Copyright 2020 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package test

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

func TestHMDbgTracing(t *testing.T) {
	numServers := 3
	numClusters := 8
	sc := createSuperCluster(t, numServers, numClusters)
	defer sc.shutdown()

	selectServer := func() *server.Options {
		si, ci := rand.Int63n(int64(numServers)), rand.Int63n(int64(numClusters))
		return sc.clusters[ci].opts[si]
	}

	nc := clientConnectWithName(t, selectServer(), "sys", "ngs-hm-dbg")
	defer nc.Close()

	// Now mimic the HM
	replyRoot := nc.NewRespInbox()
	// Subscribe to wildcard because we are going to add a request ID and start time.
	sub, err := nc.SubscribeSync(replyRoot + ".>")
	if err != nil {
		t.Fatalf("Unable to create subscription: %v", err)
	}
	sub.SetPendingLimits(-1, -1)

	reqID := 222
	reply := fmt.Sprintf("%s.%v.%v", replyRoot, reqID, time.Now().UnixNano())
	if err := nc.PublishRequest("$SYS.REQ.SERVER.PING", reply, nil); err != nil {
		t.Fatalf("Error publishing request: %v\n", err)
	}

	expected := numServers * numClusters
	checkFor(t, time.Second, 10*time.Millisecond, func() error {
		if nmsgs, _, _ := sub.Pending(); err != nil || nmsgs != expected {
			return fmt.Errorf("Did not receive correct number of messages: %d vs %d", nmsgs, expected)
		}
		return nil
	})

	//rmsg, err := sub.NextMsg(time.Second)
	//fmt.Printf("reply looks like %s\n", rmsg.Data)
}
