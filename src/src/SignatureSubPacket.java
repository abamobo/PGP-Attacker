package src;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;


public class SignatureSubPacket extends Packet{
	
	private ArrayList<Byte> body = new ArrayList<Byte>();
	private PubKeyPacket pubKey = null;
	private Packet toBeSigned = null;
	private HashAlgorithms hashAlgo = null;
	private SigSubTypes sigSubType;
	private boolean holdsString = false; // this is used to get the info, wheter a payload can be placed inseide this subpacket
	
	public boolean isCapableOfHoldingPayload(){
		return this.holdsString;
	}
	public SigSubTypes getSigSubType(){
		return this.sigSubType;
	}
	
	public SignatureSubPacket(SigSubTypes sigSubType){
		this(sigSubType, null,null,null);
	}

	public SignatureSubPacket(SigSubTypes sigSubType,String payload){
		this(sigSubType, payload, null,null);
	}
	public SignatureSubPacket(SigSubTypes sigSubType, PubKeyPacket pubKey){
		this(sigSubType, null, pubKey, null);
	}	
	
	SignatureSubPacket(SigSubTypes sigSubType, String payload, PubKeyPacket pubKey, HashAlgorithms hashAlgo){
		this.sigSubType = sigSubType;
		this.pubKey = pubKey;
		this.hashAlgo = hashAlgo;
		switch (sigSubType){
		/*case EMBEDDED_SIGNATURE: // no support yet
			bWriteEMBEDDED_SIGNATURE(payload);			
			break;*/
		case EXPORTABLE_CERTIFICATION:
			bWriteEXPORTABLE_CERTIFICATION();			
			break;
		case FEATURES: 
			bWriteFEATURES();			
			break;
		case ISSUER:
			bWriteISSUER();			
			break;
		case KEY_EXPIRATION_TIME: 
			bWriteKEY_EXPIRATION_TIME();			
			break;
		case KEY_FLAGS:
			bWriteKEY_FLAGS();			
			break;
		case KEY_SERVER_PREFERENCES: 
			bWriteKEY_SERVER_PREFERENCES();			
			break;
		case NOTATION_DATA: 
			bWriteNOTATION_DATA(payload);			
			break;
		case POLICY_URI: 
			bWritePOLICY_URI(payload);			
			break;
		case PREFERRED_COMPRESSION_ALGORITHMS:
			bWritePREFERRED_COMPRESSION_ALGORITHMS();			
			break;
		case PREFERRED_HASH_ALGORITHMS:
			bWritePREFERRED_HASH_ALGORITHMS();			
			break;
		case PREFERRED_KEY_SERVER: 
			bWritePREFERRED_KEY_SERVER(payload);			
			break;
		case PREFERRED_SYMMETRIC_ALGORITHMS:
			bWritePREFERRED_SYMMETRIC_ALGORITHMS();			
			break;
		case PRIMARY_USER_ID: 
			bWritePRIMARY_USER_ID();			
			break;
		case REASON_FOR_REVOCATION:
			bWriteREASON_FOR_REVOCATION(payload);			
			break;
		case REGULAR_EXPRESSION: 
			bWriteREGULAR_EXPRESSION(payload);			
			break;
		case REVOCABLE: 
			bWriteREVOCABLE();			
			break;
		case REVOCATION_KEY: 
			bWriteREVOCATION_KEY();			
			break;
		case SIGNATURE_CREATION_TIME:
			bWriteSIGNATURE_CREATION_TIME();			
			break;
		case SIGNATURE_EXPIRATION_TIME:
			bWriteSIGNATURE_EXPIRATION_TIME();			
			break;
		case SIGNATURE_TARGET:
			bWriteSIGNATURE_TARGET();			
			break;
		case SIGNERS_USER_ID:
			bWriteSIGNERS_USER_ID(payload);			
			break;
		case TRUST_SIGNATURE:
			bWriteTRUST_SIGNATURE();			
			break;
		default:
			System.err.println("how did you manage to spcify this SignatureSubType????? "+sigSubType);
		}
		
		//done wrting the subpacket specific data to the body
		//add header to whole
		int bodyLen = body.size();
		bodyLen++; // includes subpacket type
		byte[] data = null;//header 
		if (bodyLen > 0 && bodyLen <= 191){ //TODO:test
			data = new byte[1];
			data[0] = (byte) bodyLen;
		}
		else if(bodyLen >= 192 && bodyLen <= 8383){
			data = new byte[2];
			data[0] = (byte) (((bodyLen-192)>> 8)+192);
			data[1] = (byte) ( bodyLen - 192 - ((data[0]-192)<<8));//TODO ---------------------------------wirklich data[1] ???????????????????
			/*System.out.println((byte) ((bodyLen-192)/256+192) );
			System.out.println("data[1] "+data[1]);
			System.out.println("data[2] "+data[2]);*/
		}
		else if (bodyLen >= 8384 && bodyLen <= 0xFFFFFFFFL){ 
			data = new byte[5];
			data[0] = (byte) 255;
			data[1] = (byte) (bodyLen >> 24);
			data[2] = (byte) (bodyLen >> 16);
			data[3] = (byte) (bodyLen >> 8);
			data[4] = (byte) (bodyLen >> 0);
		}
		System.out.println();
		System.out.println("adding "+sigSubType);
		
		//add header length to whole
		for (int i=0; i<data.length; i++){
			whole.add(data[i]);
		}
		
		// add rest of header to whole Packet
		whole.add(sigSubType.getNum()); // sets the subpacket type
		System.out.println("header: " + Arrays.toString(this.getWholePacket()));
		//add body to whole
		for (int i=0; i<body.size(); i++){
			whole.add(body.get(i));
		}
		System.out.println("whole: "+ Arrays.toString(this.getWholePacket()));
		
		System.out.println("end adding "+sigSubType);
		System.out.println();
	}

	/*private void bWriteEMBEDDED_SIGNATURE(String payload) {
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.26
		 */
		
		/*System.err.println("not supported");
	}*/

	private void bWriteEXPORTABLE_CERTIFICATION() {
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.11
		 */
		body.add((byte) 0x01); //exportable signautre flag is set
		
	}

	private void bWriteFEATURES() {
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.24
		 */
		body.add((byte) 0x00);//no extra features
		
	}

	private void bWriteISSUER() {
		/*
		 * (8-octet Key ID)
   			The OpenPGP Key ID of the key issuing the signature.
		 */
		if(pubKey == null){
			System.err.println("for the issuer signature subpacket a pubKey has to be specified");
		}
		for (int i=0; i<8; i++){
			body.add(pubKey.getKeyID()[i]);
		}
		
	}

	private void bWriteKEY_EXPIRATION_TIME() {
		/*
		 * let the key be valid for 5 days (should be enough for testing) TODO: look here
		 */
		/*
		 * (4-octet time field)

   The validity period of the key.  This is the number of seconds after
   the key creation time that the key expires.  If this is not present
   or has a value of zero, the key never expires.  This is found only on
   a self-signature.
		 */
		long time = (System.currentTimeMillis() / 1000); // ger current time in seconds
		time += 432000;//add 5 days in seconds 5days = 5*24h = 120 hours = 120*60 Minutes = 7200 Minutes = 7200*60 Seconds = 432000 Seconds 
		
		/*body.add( (byte) (time >> 24));
		body.add( (byte) (time >> 16));
		body.add( (byte) (time >>  8));
		body.add( (byte) (time >>  0));
		*/
		body.add( (byte) 0x01);
		body.add( (byte) 0x02);
		body.add( (byte) 0x03);
		body.add( (byte) 0x04);
	}

	private void bWriteKEY_FLAGS() {
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.21
		 */
		//key can be used for anything:
		byte flag = (byte) 0x01;// This key may be used to certify other keys.
		flag += (byte) 0x02;// This key may be used to sign data.
		flag += (byte) 0x04;//This key may be used to encrypt communications.
		flag += (byte) 0x08;//This key may be used to encrypt storage.
		flag += (byte) 0x20;//This key may be used for authentication.
		
		body.add(flag);
	}

	private void bWriteKEY_SERVER_PREFERENCES() {
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.17
		 */
		body.add((byte) 0x80);
	}

	private void bWriteNOTATION_DATA(String payload) {
		if(payload == null){
			System.err.println(" for the NOTATION_DATA SignatureSubPacket a payload has to be specified");
		}
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.16
		 */
		body.add((byte) 0x80);//human readable text
		body.add((byte) 0x00);
		body.add((byte) 0x00);
		body.add((byte) 0x00);
		
		byte[] data = Util.payload2Barr(payload);
		//add length to name data
		Scalar scal = new Scalar(data.length,2);
		body.add(scal.getWholeScalar()[0]);
		body.add(scal.getWholeScalar()[1]);
		bWriteString(payload);
		
		body.add(scal.getWholeScalar()[0]);
		body.add(scal.getWholeScalar()[1]);

		this.holdsString = true;
		bWriteString(payload);
	}

	private void bWritePOLICY_URI(String payload) {
		if(payload == null){
			System.err.println(" for the NOTATION_DATA SignatureSubPacket a payload has to be specified");
		}
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.20
		 */

		this.holdsString = true;
		this.bWriteString(payload);
	}

	private void bWritePREFERRED_COMPRESSION_ALGORITHMS() {
		/*
		 * (array of one-octet values)

   Compression algorithm numbers that indicate which algorithms the key
   holder prefers to use.  Like the preferred symmetric algorithms, the
   list is ordered.  Algorithm numbers are in Section 9.  If this
   subpacket is not included, ZIP is preferred.  A zero denotes that
   uncompressed data is preferred; the key holder's software might have
   no compression software in that implementation.  This is only found
   on a self-signature.
		 */
		body.add((byte) 0x00); //no compression preferred
		
	}

	private void bWritePREFERRED_HASH_ALGORITHMS() {
		/*
		 * (array of one-octet values)

		   Message digest algorithm numbers that indicate which algorithms the
		   key holder prefers to receive.  Like the preferred symmetric
		   algorithms, the list is ordered.  Algorithm numbers are in Section 9.
		   This is only found on a self-signature.
		 */
		
		body.add(HashAlgorithms.MD5.getNum()); // only three supported
		body.add(HashAlgorithms.SHA1.getNum());
		body.add(HashAlgorithms.SHA256.getNum());
		
	}

	private void bWritePREFERRED_KEY_SERVER(String payload) {
		if(payload == null){
			System.err.println(" for the NOTATION_DATA SignatureSubPacket a payload has to be specified");
		}
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.18
		 */

		this.holdsString = true;
		bWriteString(payload);
	}

	private void bWritePREFERRED_SYMMETRIC_ALGORITHMS() {
		/*
		 *  (array of one-octet values)

   Symmetric algorithm numbers that indicate which algorithms the key
   holder prefers to use.  The subpacket body is an ordered list of
   octets with the most preferred listed first.  It is assumed that only 
		 */
		body.add((byte) 0x01); // add just two random algos
		body.add((byte) 0x02);
	}

	private void bWritePRIMARY_USER_ID() {
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.19
		 */
		body.add((byte) 0x00);//is not primary User id
	}

	private void bWriteREASON_FOR_REVOCATION(String payload) {
		if(payload == null){
			System.err.println(" for the NOTATION_DATA SignatureSubPacket a payload has to be specified");
		}
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.23
		 */
		
		body.add((byte) 0x00);//no reason
		this.bWriteString(payload);
	}

	private void bWriteREGULAR_EXPRESSION(String payload) {
		if(payload == null){
			System.err.println(" for the NOTATION_DATA SignatureSubPacket a payload has to be specified");
		}
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.14
		 */

		this.holdsString = true;
		bWriteString(payload);
		body.add((byte) 0x00); //null terminated string, Strings are not null terminated in java
	}

	private void bWriteREVOCATION_KEY() {
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.15
		 */
		if(pubKey == null){
			System.err.println("for the REVOCATION_KEY signature subpacket a keyiD has to be specified");
		}
		body.add((byte) 0x80);//has to be set
		
		body.add((byte) 0x01);//public key algo id
		
		//fingerprint
		for (int i=0; i<20; i++){
			body.add(pubKey.getFingerprint()[i]);
		}
		
	}

	private void bWriteREVOCABLE() {
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.12
		 * (1 octet of revocability, 0 for not, 1 for revocable)
		 */
		body.add((byte) 0x01); // signature is revokable
	}

	private void bWriteSIGNATURE_EXPIRATION_TIME() {
		/*
		 *  (4-octet time field)

   The validity period of the signature.  This is the number of seconds
   after the signature creation time that the signature expires.  If
   this is not present or has a value of zero, it never expires.
		 */
		int time = (int)(System.currentTimeMillis() / 1000); // ger current time in seconds
		time += 432000;//add 5 days in seconds 5days = 5*24h = 120 hours = 120*60 Minutes = 7200 Minutes = 7200*60 Seconds = 432000 Seconds 
		
		/*body.add( (byte) (time >> 24));
		body.add( (byte) (time >> 16));
		body.add( (byte) (time >>  8));
		body.add( (byte) (time >>  0));*/
		body.add( (byte) 0x01);
		body.add( (byte) 0x02);
		body.add( (byte) 0x03);
		body.add( (byte) 0x04);
		
	}

	private void bWriteSIGNATURE_CREATION_TIME() {
		/*(4-octet time field)
   The time the signature was made.
   MUST be present in the hashed area.*/
		int time = (int)(System.currentTimeMillis() / 1000); // ger current time in seconds
		
		/*body.add( (byte) (time >> 24));
		body.add( (byte) (time >> 16));
		body.add( (byte) (time >>  8));
		body.add( (byte) (time >>  0));*/
		
		body.add( (byte) 0x01);
		body.add( (byte) 0x02);
		body.add( (byte) 0x03);
		body.add( (byte) 0x04);
		
	}

	private void bWriteSIGNATURE_TARGET() {
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.25
		 */
		if(pubKey == null){
			System.err.println("for the SIGNATURE_TARGET " +
					" subpacket a keyiD has to be specified");
		}
		if(hashAlgo == null){
			System.err.println("for the SIGNATURE_TARGET subpacket a hashAlgo has to be specified");
		}
		body.add((byte) pubKey.getPubKeyAlgo().getNum());//random pubkeyalgo
		body.add((byte) this.hashAlgo.getNum());
		byte[] data = null;
		switch(hashAlgo){//TODO: maybe real hash, instead of zero bytes?
		case MD5:
			data = new byte[16];
			break;
		case SHA1:
			data = new byte[20];
			break;
		case SHA256:
			data = new byte[32];
			break;
		default:
			System.err.println("sigsubpacket bwritesignature_target");
		}
		for (int i=0; i<data.length; i++){
			body.add((byte) data[i]);
		}
	}

	private void bWriteSIGNERS_USER_ID(String payload) {
		if(payload == null){
			System.err.println(" for the SIGNERS_USER_ID SignatureSubPacket a payload has to be specified");
		}
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.22
		 */
		this.holdsString = true;
		this.bWriteString(payload);
	}

	private void bWriteTRUST_SIGNATURE() {
		/*
		 * https://tools.ietf.org/html/rfc4880#section-5.2.3.13
		 */
		body.add((byte) 0x00);//ordinary validity signature
		
	}
	
	
	/*
	 * add specified payload String to body
	 */
	private void bWriteString(String payload){
		
		byte[] data = Util.payload2Barr(payload);
		for (int i=0; i<data.length;i++){
			body.add(data[i]);
		}
	}
	
	
}
