package otr3

import "testing"

func Test_Conversation_eventHandler_returnsAndSetsAndEmptyEventHandlerIfNoneExist(t *testing.T) {
	c := &Conversation{}

	ev := c.getEventHandler()
	ev2 := ev.(dynamicEventHandler)
	assertFuncEquals(t, ev2.handleErrorMessage, emptyErrorMessageHandler)
	assertFuncEquals(t, ev2.handleSMPEvent, emptySMPEventHandler)
	assertFuncEquals(t, ev2.handleMessageEvent, emptyMessageEventHandler)
	assertNotNil(t, c.eventHandler)
}

func Test_Conversation_eventHandler_returnsAnExistingEventHandlerIfItExists(t *testing.T) {
	c := &Conversation{}
	c.eventHandler = dynamicEventHandler{}

	ev := c.getEventHandler()
	ev2 := ev.(dynamicEventHandler)
	assertNil(t, ev2.handleMessageEvent)
}

func Test_Conversation_eventHandler_doesntSetEventHandlerIfOneExists(t *testing.T) {
	c := &Conversation{}
	c.eventHandler = dynamicEventHandler{}

	c.getEventHandler()
	ev2 := c.eventHandler.(dynamicEventHandler)
	assertNil(t, ev2.handleMessageEvent)
}
