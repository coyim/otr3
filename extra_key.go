package otr3

func (c *Conversation) processExtraSymmetricKeyTLV(t tlv, x dataMessageExtra) (toSend *tlv, err error) {
	rest, usage, ok := extractWord(t.tlvValue[:t.tlvLength])
	if ok {
		c.receivedSymKey(usage, rest, x.key)
	}
	return nil, nil
}

func (c *Conversation) UseExtraSymmetricKey() ([]byte, []ValidMessage, error) {
	// /* Get the current extra symmetric key (of size OTRL_EXTRAKEY_BYTES
	//  * bytes) and let the other side know what we're going to use it for.
	//  * The key is stored in symkey, which must already be allocated
	//  * and OTRL_EXTRAKEY_BYTES bytes long. */
	// gcry_error_t otrl_message_symkey(OtrlUserState us,
	// 	const OtrlMessageAppOps *ops, void *opdata, ConnContext *context,
	// 	unsigned int use, const unsigned char *usedata, size_t usedatalen,
	// 	unsigned char *symkey)
	// {
	//     if (!context || (usedatalen > 0 && !usedata)) {
	// 	return gcry_error(GPG_ERR_INV_VALUE);
	//     }

	//     if (context->msgstate == OTRL_MSGSTATE_ENCRYPTED &&
	// 	    context->context_priv->their_keyid > 0) {
	// 	unsigned char *tlvdata = malloc(usedatalen+4);
	// 	char *encmsg = NULL;
	// 	gcry_error_t err;
	// 	OtrlTLV *tlv;

	// 	tlvdata[0] = (use >> 24) & 0xff;
	// 	tlvdata[1] = (use >> 16) & 0xff;
	// 	tlvdata[2] = (use >> 8) & 0xff;
	// 	tlvdata[3] = (use) & 0xff;
	// 	if (usedatalen > 0) {
	// 	    memmove(tlvdata+4, usedata, usedatalen);
	// 	}

	// 	tlv = otrl_tlv_new(OTRL_TLV_SYMKEY, usedatalen+4, tlvdata);
	// 	free(tlvdata);

	// 	err = otrl_proto_create_data(&encmsg, context, "", tlv,
	// 		OTRL_MSGFLAGS_IGNORE_UNREADABLE, symkey);
	// 	if (!err && ops->inject_message) {
	// 	    ops->inject_message(opdata, context->accountname,
	// 		    context->protocol, context->username, encmsg);
	// 	}
	// 	free(encmsg);
	// 	otrl_tlv_free(tlv);

	// 	return err;
	//     }

	//     /* We weren't in an encrypted session. */
	//     return gcry_error(GPG_ERR_INV_VALUE);
	// }

	return nil, nil, nil
}

// ReceivedKeyHandler is an interface that will be invoked when an extra key is received
type ReceivedKeyHandler interface {
	// ReceivedSymmetricKey will be called when a TLV requesting the use of a symmetric key is received
	ReceivedSymmetricKey(usage uint32, usageData []byte, symkey []byte)
}

type dynamicReceivedKeyHandler struct {
	eh func(usage uint32, usageData []byte, symkey []byte)
}

func (d dynamicReceivedKeyHandler) ReceivedSymmetricKey(usage uint32, usageData []byte, symkey []byte) {
	d.eh(usage, usageData, symkey)
}

func (c *Conversation) receivedSymKey(usage uint32, usageData []byte, symkey []byte) {
	if c.receivedKeyHandler != nil {
		c.receivedKeyHandler.ReceivedSymmetricKey(usage, usageData, symkey)
	}
}
