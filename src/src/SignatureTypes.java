package src;
//https://tools.ietf.org/html/rfc4880#section-5.2.1
/*
 * commented signature types are not needed for transferable public keys
 */
public enum SignatureTypes {
	//SIGNATURE_OF_A_BINARY_DOCUMENT(0x00),
	//SIGNATURE_OF_A_CANONICAL_TEXT_DOCUMENT(0x01),
	//STANDALONE_SIGNATURE(0x02),
	//GENERIC_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET(0x10),
	//PERSONA_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET(0x11),
	//CASUAL_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET(0x12),
	POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET(0x13), // we will be using only this one 
	SUBKEY_BINDING_SIGNATURE(0x18),
	PRIMARY_KEY_BINDING_SIGNATURE(0x19),
	//SIGNATURE_DIRECTLY_ON_A_KEY(0x1F),
	KEY_REVOCATION_SIGNATURE(0x20),
	SUBKEY_REVOCATION_SIGNATURE(0x28);
	//CERTIFICATION_REVOCATION_SIGNATURE(0x30),
	//TIMESTAMP_SIGNATURE(0x40),
	//THIRD_PARTY_CONFIRMATION_SIGNATURE(0x50);
	
	
	private byte num;
	
	SignatureTypes(int num){
		this.num = (byte) num;
	}
	
	public byte getNum(){
		return this.num;
	}
}
