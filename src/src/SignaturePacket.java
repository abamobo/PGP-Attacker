package src;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

/*
 * https://tools.ietf.org/html/rfc4880#section-5.2.3
 * Note I will only be creating v4 Packets
 */
public class SignaturePacket  extends Packet{
	private byte[] digest = null;
	private int version;
	private int bOffsetSizeUnhashed;
	private byte[] keyID;
	private ArrayList<SignatureSubPacket> hashedSubPackets;
	private ArrayList<SignatureSubPacket> unHashedSubPackets;
	
	public ArrayList<SignatureSubPacket> getHashedSubpackets(){
		return this.hashedSubPackets;
	}
	
	public ArrayList<SignatureSubPacket> getUnhashedSubpackets(){
		return this.unHashedSubPackets;
	}
	public SignatureSubPacket getHashedSubpacket(int num){
		return this.hashedSubPackets.get(num);
	}
	public SignatureSubPacket getUnhashedSubpacket(int num){
		return this.unHashedSubPackets.get(num);
	}
	
	public int getNumHashedSubPackets(){
		return this.hashedSubPackets.size();
	}
	public int getNumUnhashedSubPackets(){
		return this.unHashedSubPackets.size();
	}
	public int getNumHashedSubPacketsWhichCanHoldPayload(){
		int ctr = 0;
		for (int i = 0; i< this.hashedSubPackets.size(); i++){
			if (this.hashedSubPackets.get(i).isCapableOfHoldingPayload()){
				ctr++;
			}
		}
		return ctr;
	}
	public int getNumUnhashedSubPacketsWhichCanHoldPayload(){
		int ctr = 0;
		for (int i = 0; i< this.unHashedSubPackets.size(); i++){
			if (this.unHashedSubPackets.get(i).isCapableOfHoldingPayload()){
				ctr++;
			}
		}
		return ctr;
	}
	/**
	 * @param sigType specifies the type of the Signature
	 * @param pubKeyAlgo specifies the used PublicKey Algorithm, has to be the same as in the first public key
	 * @param hashAlgo specifies the type of Hash Alogrithm used
	 * @param hashedSubPackets is an ArrayList<SignatureSubPacket>  of all SignatureSubPacket which are to be hashed
	 * @param unHashedSubPackets is an ArrayList<SignatureSubPacket>  of all SignatureSubPacket which are NOT to be hashed
	 */
	public SignaturePacket(int version, 
					SignatureTypes sigType,
					PubKeyAlgos pubKeyAlgo,
					HashAlgorithms hashAlgo,
					ArrayList<SignatureSubPacket> hashedSubPackets, 
					ArrayList<SignatureSubPacket> unHashedSubPackets,
					byte[] payload, 
					Packet pack, 
					PubKeyPacket pubKey) {
		this.version = version;
		this.unHashedSubPackets = unHashedSubPackets;
		this.hashedSubPackets = hashedSubPackets;
		bSetVersionNum((byte) version);
		
		/*
		 * set keyid
		 */
		this.keyID  = pubKey.getKeyID();
		
		
		//md is used for the signature generation
		MessageDigest md = null;// create a new instance of an messagedigest
		try {
			md = MessageDigest.getInstance(hashAlgo.toString());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.err.println("This cannot hapen, since only supported hashAlgos are specified in HashAlgorithms class");
		}
		
		
		if (version == 3){
			body.add((byte) 0x05); // fix size of 5 for hashed material
			
			body.add((byte) sigType.getNum()); // wirte signature type
			
			body.add((byte) 0x01);//begin creation time
			body.add((byte) 0x02);
			body.add((byte) 0x03);
			body.add((byte) 0x04);//end creation time
			
			for (int i=0; i<8; i++){ // add 8 byte key id
				body.add((byte) pubKey.getKeyID()[i]);
			}
			
			body.add((byte) pubKeyAlgo.getNum()); // public-key algorithm
			body.add((byte) hashAlgo.getNum()); // hash algorithm
			
		}
		else if (version == 4){
			bSetSigType(sigType);
			bSetPubKeyAlgo(pubKeyAlgo);
			bsetHashAlgo(hashAlgo);
			
			System.out.println("before scalar hashedsubPackets: "+Arrays.toString(this.getBody()));
			bWriteScalar(hashedSubPackets);
			System.out.println("before  hashedsubPackets: "+Arrays.toString(this.getBody()));
			bWriteSubPackets(hashedSubPackets);
			bOffsetSizeUnhashed = body.size();
			System.out.println("before scalar U N hashedsubPackets: "+Arrays.toString(this.getBody()));
			bWriteScalar(unHashedSubPackets);
			System.out.println("before U N hashedsubPackets: "+Arrays.toString(this.getBody()));
			bWriteSubPackets(unHashedSubPackets);
			
			
		}
		else{
			System.err.println("signature pack generation invalid verion number speicified");
		}
		
		
		bWriteSignature(md, sigType, pack);
		
		//body is complete
		//add header to whole
		head = new Header(PacketTags.SIG, body.size());
		for (int i=0; i<head.getLength(); i++){
			whole.add((byte) head.getWholeHeader()[i]);
		}
		System.out.println("header of signature: " +Util.ByteArr2String(getWholePacket()));
		
		//add body to whole
		for (int i=0; i<body.size(); i++){
			whole.add(body.get(i));
		}
		System.out.println("whole package: " +Util.ByteArr2String(getWholePacket()));
	}
	
	private void bWriteSignature(MessageDigest md, SignatureTypes sigType,Packet pack) {
		//https://tools.ietf.org/html/rfc4880#section-5.2.4
		/*
		 * When a signature is made over a key, the hash data starts with the
   octet 0x99, followed by a two-octet length of the key, and then body
   of the key packet.  (Note that this is an old-style packet header for
   a key packet with two-octet length.)  A subkey binding signature
   (type 0x18) or primary key binding signature (type 0x19) then hashes
   the subkey using the same format as the main key (also using 0x99 as
   the first octet).  Key revocation signatures (types 0x20 and 0x28)
   hash only the key being revoked.
		 */
		/*
		 *  A certification signature (type 0x10 through 0x13) hashes the User
   ID being bound to the key into the hash context after the above
   data.  A V3 certification hashes the contents of the User ID or
   attribute packet packet, without any header.  A V4 certification
   hashes the constant 0xB4 for User ID certifications or the constant
   0xD1 for User Attribute certifications, followed by a four-octet
   number giving the length of the User ID or User Attribute data, and
   then the User ID or User Attribute data.
		 */
		
		ArrayList<Byte> toBeHashed = new ArrayList<Byte>();
		/*
		 * this switch fills only the toBeHashed arraylist, the actual generation will be performed at the bottom of the function
		 */
		switch (sigType){
		case POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
			/*0x13: Positive certification of a User ID and Public-Key packet.
       The issuer of this certification has done substantial
       verification of the claim of identity.

       Most OpenPGP implementations make their "key signatures" as 0x10
       certifications.  Some implementations can issue 0x11-0x13
       certifications, but few differentiate between the types.*/
			if (this.version == 4){
					
				
				/*
				 * A V4 certification
	   hashes the constant 0xB4 for User ID certifications or the constant
	   0xD1 for User Attribute certifications, followed by a four-octet
	   number giving the length of the User ID or User Attribute data, and
	   then the User ID or User Attribute data.
				 */
				if ( !(pack instanceof UserIDPacket)  && !(pack instanceof UserAttributePacket)){
					System.err.println("one cannot compute and positive certifcation signature on a Packet which is not an user id or user attribute, but a "+pack.getClass());
				}
				if (pack instanceof UserIDPacket){
					System.out.println("A UserIDPacket is to be signed");
					toBeHashed.add((byte) 0xB4); 				
				}
				else if (pack instanceof UserAttributePacket){
					System.out.println("A User Attribute is to be signed");
					toBeHashed.add((byte) 0xD1);
				}
				
				Scalar scal = new Scalar(pack.getWholePacketSize(),4); // write 4 bytes size
				toBeHashed.add((byte) scal.getWholeScalar()[0]);
				toBeHashed.add((byte) scal.getWholeScalar()[1]);
				toBeHashed.add((byte) scal.getWholeScalar()[2]);
				toBeHashed.add((byte) scal.getWholeScalar()[3]);
				int bodyOffset = pack.getHeaderLength();
	
				byte[] packet2beSigned = pack.getWholePacket();
				
				for (int i=bodyOffset; i<pack.getWholePacketSize(); i++){
					toBeHashed.add((byte) packet2beSigned[i]);
				}
			}
			else if (version == 3){
				/*
				 * The concatenation of the data to be signed, the signature type, and
				   creation time from the Signature packet (5 additional octets) is
				   hashed.  The resulting hash value is used in the signature algorithm.
				   The high 16 bits (first two octets) of the hash are included in the
				   Signature packet to provide a quick test to reject some invalid
				   signatures.
				 */
				int bodyOffset = pack.getHeaderLength();
				byte[] packet2beSigned = pack.getWholePacket();
				for (int i=bodyOffset; i<pack.getWholePacketSize(); i++){ // add whole packet tot the to be signed byte array //TODO verify whole Packet?
					toBeHashed.add((byte) packet2beSigned[i]);
				}
				toBeHashed.add( (byte) sigType.getNum());
				toBeHashed.add( (byte) 0x01 ); // add time 01020304 is my standard time, //TODO: change to time over a parameter
				toBeHashed.add( (byte) 0x02 );
				toBeHashed.add( (byte) 0x03 );
				toBeHashed.add( (byte) 0x04 );
				
				//TODO: finish
			}
			break;
		case SUBKEY_BINDING_SIGNATURE:
			/*
			 * This signature is a statement by the top-level signing key that
       indicates that it owns the subkey.  This signature is calculated
       directly on the primary key and subkey, and not on any User ID or
       other packets.  A signature that binds a signing subkey MUST have
       an Embedded Signature subpacket in this binding signature that
       contains a 0x19 signature made by the signing subkey on the
       primary key and subkey.

			 */
			if (pack instanceof SubKeyPacket){
				System.out.println("A SubKeyPacket is to sign");
			}
			else{
				System.err.println("one cannot SUBKEY_BINDING_SIGNATURE on a Packet which is not an SubKeyPacket, but a "+pack.getClass());
			}
			break;
			
		case PRIMARY_KEY_BINDING_SIGNATURE:
			/*
			 * This signature is a statement by a signing subkey, indicating
       that it is owned by the primary key and subkey.  This signature
       is calculated the same way as a 0x18 signature: directly on the
       primary key and subkey, and not on any User ID or other packets.
			 */
			if (pack instanceof SubKeyPacket){
				System.out.println("A SubKeyPacket is to sign");
			}
			else{
				System.err.println("one cannot comute a  PRIMARY_KEY_BINDING_SIGNATURE on a Packet which is not an SubKeyPacket, but a "+pack.getClass());
			}
			break;
			
		case KEY_REVOCATION_SIGNATURE:
			/*
			 * The signature is calculated directly on the key being revoked.  A
       revoked key is not to be used.  Only revocation signatures by the
       key being revoked, or by an authorized revocation key, should be
       considered valid revocation signatures.
			 */
			if (pack instanceof PubKeyPacket){
				System.out.println("A PubKeyPacket is to sign");
			}
			else{
				System.err.println("one cannot comute a KEY_REVOCATION_SIGNATURE on a Packet which is not an PubKeyPacket, but a "+pack.getClass());
			}
			break;
			
		case SUBKEY_REVOCATION_SIGNATURE:
			/*
			 * The signature is calculated directly on the subkey being revoked.
       A revoked subkey is not to be used.  Only revocation signatures
       by the top-level signature key that is bound to this subkey, or
       by an authorized revocation key, should be considered valid
       revocation signatures.
			 */
			if (pack instanceof SubKeyPacket){
				System.out.println("A SubKeyPacket is to sign");
			}
			else{
				System.err.println("one cannot comute a  SUBKEY_REVOCATION_SIGNATURE on a Packet which is not an SubKeyPacket, but a "+pack.getClass());
			}
			break;
			
		default:
			System.err.println("function bWriteSignature in Signature Packet: this should not happen, debug your code, dude");
		}
		
		if (this.version == 3){
			
		}
		
		else if (this.version == 4){
			
			for (int i=0; i<bOffsetSizeUnhashed; i++){ // add body from version number up to tobe hashed subpackets to tobehashed arraylist
				toBeHashed.add(body.get(i));
			}
			
			/*
			 * https://tools.ietf.org/html/rfc4880#section-5.2.4
			 * append trailer
			 */
			toBeHashed.add((byte) this.version);// version
			toBeHashed.add((byte) 0xFF);// this is a fixed constatnt
			//rest is four byte len scalar of the tobehashed arrays sze
			Scalar scal = new Scalar(toBeHashed.size(),4);
			toBeHashed.add((byte) scal.getWholeScalar()[0]);
			toBeHashed.add((byte) scal.getWholeScalar()[1]);
			toBeHashed.add((byte) scal.getWholeScalar()[2]);
			toBeHashed.add((byte) scal.getWholeScalar()[3]);
			
			/*
			 * compute message digest
			 */
			byte[] dataToBeHashed = new byte[toBeHashed.size()];
			for(int i=0; i<dataToBeHashed.length; i++){
				dataToBeHashed[i] = toBeHashed.get(i);
			}
			
			byte[] digest = md.digest(dataToBeHashed);
			this.digest = digest;		
			/*
			 * write low 16 bits of hash
			 */
			body.add((byte) digest[0]);
			body.add((byte) digest[1]);
			/*
			 * write computed signature to body
			 */
			scal = new Scalar(digest.length*8,2);//size in bits for MPI
			body.add((byte) scal.getWholeScalar()[0]);
			body.add((byte) scal.getWholeScalar()[1]);
			for(int i=0; i<digest.length; i++){
				body.add( (byte) digest[i]);
			}
		}
	}

	private void bWriteScalar(ArrayList<SignatureSubPacket> subPackets) {
		Scalar scalSubPacket = new Scalar(getLenOfSubPackets(subPackets),2);
		this.body.add(scalSubPacket.getWholeScalar()[0]);
		this.body.add(scalSubPacket.getWholeScalar()[1]);
	}

	private void bWriteSubPackets(ArrayList<SignatureSubPacket> subPackets) {
		byte[] tmp = null;
		for (int i=0; i<subPackets.size();i++){
			tmp = subPackets.get(i).getWholePacket();
			for(int j=0; j<tmp.length;j++){
				body.add(tmp[j]);
			}
		}		
	}

	/*
	 * calculates the length in bytes of an arraylist of subpackets
	 */
	private long getLenOfSubPackets(ArrayList<SignatureSubPacket> subPackets){
		long len = 0;
		
		for(int i=0; i<subPackets.size();i++){
			len += subPackets.get(i).getWholePacketSize();
		}
		
		return len;
	}
	
	private void bsetHashAlgo(HashAlgorithms hashAlgo) {
		this.body.add(hashAlgo.getNum());
	}

	private void bSetPubKeyAlgo(PubKeyAlgos pubKeyAlgo) {
		this.body.add(pubKeyAlgo.getNum());		
	}

	private void bSetSigType(SignatureTypes sigType) {
		this.body.add(sigType.getNum());
	}

	private void  bSetVersionNum(byte b) {
		this.body.add(b);		
	}
	
	public byte[] getDigest(){
		return this.digest;
	}
	
}
