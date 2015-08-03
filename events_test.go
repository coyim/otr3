package otr3

import "testing"

func Test_Conversation_eventHandler_returnsAndSetsAndEmptyEventHandlerIfNoneExist(t *testing.T) {
	c := &Conversation{}

	ev := c.getEventHandler()
	assertFuncEquals(t, ev.errorMessage, emptyErrorMessageHandler)
	assertFuncEquals(t, ev.handleSMPEvent, emptySMPEventHandler)
	assertFuncEquals(t, ev.handleMessageEvent, emptyMessageEventHandler)
	assertNotNil(t, c.eventHandler)
}

func Test_Conversation_eventHandler_returnsAnExistingEventHandlerIfItExists(t *testing.T) {
	c := &Conversation{}
	before := &EventHandler{}
	c.eventHandler = before

	ev := c.getEventHandler()
	assertEquals(t, ev, before)
}

func Test_Conversation_eventHandler_doesntSetEventHandlerIfOneExists(t *testing.T) {
	c := &Conversation{}
	before := &EventHandler{}
	c.eventHandler = before

	c.getEventHandler()
	assertEquals(t, c.eventHandler, before)
}
