package src;
public enum SigSubTypes {
	/*
	 * reserved is uninteresting
	 */
	/*RESERVED(0),
	RESERVED(1),*/
	SIGNATURE_CREATION_TIME(2),
	SIGNATURE_EXPIRATION_TIME(3),
	EXPORTABLE_CERTIFICATION(4),
	TRUST_SIGNATURE(5),
	REGULAR_EXPRESSION(6), // very interesting //https://tools.ietf.org/html/rfc4880#section-5.2.3.14
	REVOCABLE(7),
	/*RESERVED(8),*/
	KEY_EXPIRATION_TIME(9),
	//PLACEHOLDER_FOR_BACKWARD_COMPATIBILITY(10),
	PREFERRED_SYMMETRIC_ALGORITHMS(11),
	REVOCATION_KEY(12), // interesting, 20 octets of fingerprint https://tools.ietf.org/html/rfc4880#section-5.2.3.15
	/*RESERVED(13),
	RESERVED(14),
	RESERVED(15),*/
	ISSUER(16),
	/*RESERVED(17),
	RESERVED(18),
	RESERVED(19),*/
	NOTATION_DATA(20), // interesting https://tools.ietf.org/html/rfc4880#section-5.2.3.16
	PREFERRED_HASH_ALGORITHMS(21),
	PREFERRED_COMPRESSION_ALGORITHMS(22),
	KEY_SERVER_PREFERENCES(23),
	PREFERRED_KEY_SERVER(24),//interesting https://tools.ietf.org/html/rfc4880#section-5.2.3.18
	PRIMARY_USER_ID(25),
	POLICY_URI(26), // interesting https://tools.ietf.org/html/rfc4880#section-5.2.3.20
	KEY_FLAGS(27),
	SIGNERS_USER_ID(28), // interesting https://tools.ietf.org/html/rfc4880#section-5.2.3.22
	REASON_FOR_REVOCATION(29), // https://tools.ietf.org/html/rfc4880#section-5.2.3.23
	FEATURES(30),
	SIGNATURE_TARGET(31);
	//EMBEDDED_SIGNATURE(32); no support yet	
	
	
	
	private byte num;
	
	SigSubTypes(int num){
		this.num = (byte) num;
	}
	
	public byte getNum(){
		return this.num;
	}
	
	public static SigSubTypes fromString (String inp){
		SigSubTypes type = null;
		
		switch(inp){
		case "SIGNATURE_TARGET":
			return SIGNATURE_TARGET;
		case "FEATURES":
			return FEATURES;
		case "REASON_FOR_REVOCATION":
			return REASON_FOR_REVOCATION;
		case "SIGNERS_USER_ID":
			return SIGNERS_USER_ID;
		case "KEY_FLAGS":
			return KEY_FLAGS;
		case "POLICY_URI":
			return POLICY_URI;
		case "PRIMARY_USER_ID":
			return PRIMARY_USER_ID;
		case "PREFERRED_KEY_SERVER":
			return PREFERRED_KEY_SERVER;
		case "KEY_SERVER_PREFERENCES":
			return KEY_SERVER_PREFERENCES;
		case "PREFERRED_COMPRESSION_ALGORITHMS":
			return PREFERRED_COMPRESSION_ALGORITHMS;
		case "PREFERRED_HASH_ALGORITHMS":
			return PREFERRED_HASH_ALGORITHMS;
		case "NOTATION_DATA":
			return NOTATION_DATA;
		case "REVOCATION_KEY":
			return REVOCATION_KEY;
		case "PREFERRED_SYMMETRIC_ALGORITHMS":
			return PREFERRED_SYMMETRIC_ALGORITHMS;
		case "KEY_EXPIRATION_TIME":
			return KEY_EXPIRATION_TIME;
		case "REVOCABLE":
			return REVOCABLE;
		case "REGULAR_EXPRESSION":
			return REGULAR_EXPRESSION;
		case "TRUST_SIGNATURE":
			return TRUST_SIGNATURE;
		case "EXPORTABLE_CERTIFICATION":
			return EXPORTABLE_CERTIFICATION;
		case "SIGNATURE_EXPIRATION_TIME":
			return SIGNATURE_EXPIRATION_TIME;
		case "SIGNATURE_CREATION_TIME":
			return SIGNATURE_CREATION_TIME;
		case "ISSUER":
			return ISSUER;
		default:
			System.err.println(inp+" is not a recognized type class:sigsubTypes");
		}
		
		return type;
	}
}