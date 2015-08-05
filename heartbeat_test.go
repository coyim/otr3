package otr3

import (
	"crypto/rand"
	"testing"
	"time"
)

func Test_potentialHeartbeat_returnsNothingIfThereWasntPlaintext(t *testing.T) {
	c := newConversation(otrV3{}, rand.Reader)
	c.msgState = encrypted
	var plain []byte
	ret, err := c.potentialHeartbeat(plain)
	assertNil(t, ret)
	assertNil(t, err)
}

func Test_potentialHeartbeat_returnsNothingIfLastSentWasRecently(t *testing.T) {
	c := newConversation(otrV3{}, rand.Reader)
	c.msgState = encrypted
	c.heartbeat.lastSent = time.Now().Add(-10 * time.Second)
	plain := []byte("Foo plain")
	ret, err := c.potentialHeartbeat(plain)
	assertNil(t, ret)
	assertNil(t, err)
}

func Test_potentialHeartbeat_doesntUpdateLastSentIfLastSentWasRecently(t *testing.T) {
	c := newConversation(otrV3{}, rand.Reader)
	c.msgState = encrypted
	tt := time.Now().Add(-10 * time.Second)
	c.heartbeat.lastSent = tt
	plain := []byte("Foo plain")
	c.potentialHeartbeat(plain)
	assertEquals(t, c.heartbeat.lastSent, tt)
}

func Test_potentialHeartbeat_updatesLastSentIfWeNeedToSendAHeartbeat(t *testing.T) {
	c := bobContextAfterAKE()
	c.msgState = encrypted
	tt := time.Now().Add(-61 * time.Second)
	c.heartbeat.lastSent = tt
	plain := []byte("Foo plain")
	c.potentialHeartbeat(plain)
	assertEquals(t, c.heartbeat.lastSent.After(tt), true)
}

func Test_potentialHeartbeat_logsTheHeartbeatWhenWeSendIt(t *testing.T) {
	c := bobContextAfterAKE()
	c.msgState = encrypted
	tt := time.Now().Add(-61 * time.Second)
	c.heartbeat.lastSent = tt
	plain := []byte("Foo plain")

	c.expectMessageEvent(t, func() {
		c.potentialHeartbeat(plain)
	}, MessageEventLogHeartbeatSent, nil, nil)
}

func Test_potentialHeartbeat_putsTogetherAMessageForAHeartbeat(t *testing.T) {
	c := bobContextAfterAKE()
	c.msgState = encrypted
	tt := time.Now().Add(-61 * time.Second)
	c.heartbeat.lastSent = tt
	plain := []byte("Foo plain")

	msg, err := c.potentialHeartbeat(plain)
	assertNil(t, err)
	assertDeepEquals(t, msg, messageWithHeader(bytesFromHex("0003030000010100000101010000000100000001000000C0075DFAB5A1EAB059052D0AD881C4938D52669630D61833A367155D67D03A457F619683D0FA829781E974FD24F6865E8128A9312A167B77326A87DEA032FC31784D05B18B9CBAFEBE162AE9B5369F8B0C5911CF1BE757F45F2A674BE5126A714A6366C28086B3C7088911DCC4E5FB1481AD70A5237B8E4A6AFF4954C2CA6DF338B9F08691E4C0DEFE12689B37D4DF30DDEF2687F789FCF623C5D0CF6F09B7E5E69F481D5FD1B24A77636FB676E6D733D129EB93E81189340233044766A36EB07D0000000000000000000001003868C1E198061EB15129BF772DB34F4CF8F0241EF78890AB82EDEF36CB38210BB80760585FF43D736A9FF3E4BB05FC088FA34C2F21012988D539EBC839E9BC97633F4C42DE15EA5C3C55A2B9940CA35015DED14205B9DF78F936CB1521AEDBEA98DF7DC03C116570BA8D034ABC8E2D23185D2CE225845F38C08CB2AAE192D66D601C1BC86149C98E8874705AE365B31CDA76D274429DE5E07B93F0FF29152716980A63C31B7BDA150B222BA1D373F786D5F59F580D4F690A71D7FC620E0A3B05D692221DDEEBAC98D6ED16272E7C4596DE27FB104AD747AA9A3AD9D3BC4F988AF0BEB21760DF06047E267AF0109BACEB0F363BCAFF7B205F2C42B3CB67A942F2701B7F98B35D73BEF328788883B77855F5AC7C6400000000")))
}

func Test_potentialHeartbeat_returnsAnErrorIfWeCantPutTogetherAMessage(t *testing.T) {
	c := bobContextAfterAKE()
	c.msgState = encrypted
	c.keys.ourKeyID = 0
	tt := time.Now().Add(-61 * time.Second)
	c.heartbeat.lastSent = tt
	plain := []byte("Foo plain")

	_, err := c.potentialHeartbeat(plain)
	assertDeepEquals(t, err, ErrGPGConflict)
}
