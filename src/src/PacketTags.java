package src;

public enum PacketTags {
	RESERVED(0),
	PUBKEY_ENC_SES(1),
	SIG(2),
	SYM_KEY_ENC_SES_KEY(3),
	ONE_PASS_SIG(4),
	SEC_KEY(5),
	PUB_KEY(6),
	SEC_SUB_KEY(7),
	COMPRESSED_DATA(8),
	SYM_ENC_DATA(9),
	MARKER(10),
	LITERAL_DATA(11),
	TRUST(12),
	USER_ID(13),
	PUB_SUB_KEY(14),
	USER_ATTRB(17),
	SYM_END_INTEGR_DATA(18),
	MOD_DEDECT(19),
	EXPERIMENTAL1(60),
	EXPERIMENTAL2(61),
	EXPERIMENTAL3(62),
	EXPERIMENTAL4(63);
	
	
	private byte num;
	
	PacketTags(int num){
		this.num = (byte) num;
	}
	
	public byte getNum(){
		return this.num;
	}
}
