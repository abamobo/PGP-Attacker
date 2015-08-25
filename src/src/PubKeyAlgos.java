package src;

public enum PubKeyAlgos {
	RSA_ENC_OR_SIGN(1),
	RSA_ENC(2),
	RSA_SIGN(3),
	ELGAMAL(16),
	DSA(17),
	ECC(18),
	ECDSA(19);
	
	private byte num;
	
	PubKeyAlgos(int num){
		this.num = (byte)num;
	}
	
	public byte getNum(){
		return this.num;
	}
}
