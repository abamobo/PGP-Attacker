package src;
//https://tools.ietf.org/html/rfc4880#section-9.4
public enum HashAlgorithms {
	MD5(0x01),
	SHA1(0x02),
	//RIPEMD160(0x03), // commented digests not supported by javas java.security.MessageDigest
	SHA256(0x08);
	//SHA384(0x09),
	//SHA512(0x10),
	//SHA224(0x11);
	
	
	private byte num;
	
	HashAlgorithms(int num){
		this.num = (byte) num;
	}
	
	public byte getNum(){
		return this.num;
	}

	
	public String toString(){
		String str = super.toString();
		if (this == SHA1){
			return "SHA-1";
		}
		if (this == SHA256){
			return "SHA-256";
		}
		return str;
	}
}
