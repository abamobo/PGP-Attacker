package src;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;


/*
 * Disambiguation
 * set and get specify operations on the private variables except wholePacket
 * write read specify operation on wholePacket
 */
public class PubKeyPacket extends Packet{
	/*
	 * header + body = whole Packet
	 * keyData + x = body        x = time,keytype,....
	 */
	protected Header head; // so subkey packet can change it
//	private MPI[ ] mpis;
	private int version;
	private byte[] keyData;
	protected byte[] wholePacket; // TODO: use packets object capabilities
	private byte[] fingerprint = new byte[20];
	private byte[] keyID = new byte[8];
	private PubKeyAlgos pubKeyAlgo = null;
	private byte[] time = new byte[4];
	private MPI[] mpis;
	
	public PubKeyAlgos getPubKeyAlgo(){
		return this.pubKeyAlgo;
	}
	
	private void printwholePacket(){
		//System.out.println(Arrays.toString(this.wholePacket));
	}
	private void print(Object str){
		//System.out.println(str);
	}
	/*
	 * create a new PubKeyPacket
	 */
	public PubKeyPacket(PubKeyAlgos keyType, int version, MPI[] mpis, byte[] time, byte... expirationTime){
		this.pubKeyAlgo = keyType;
		this.time = time;
		this.mpis = mpis;
		setVersion(version); // set int version // has to be first method in constructor //TODO: ckeck this later
		
		int bodyLen = calculatePacketSize(version, mpis); //whole bodysize without header
		head = new Header(PacketTags.PUB_KEY, bodyLen);
		wholePacket = new byte[bodyLen+head.getLength()];
		printwholePacket();
		writeHeader(head);
		
		
		print("writing header");
		printwholePacket();
		int offsetVersion = head.getLength();
		writeVersion(version, offsetVersion);
		print("writing version");
		printwholePacket();
		int offsetCreationTime = offsetVersion + 1;
		writeCreationTime(time, offsetCreationTime);
		print("writing CreationTime");
		printwholePacket();
		int offsetPubKeyType = offsetCreationTime +4;
		
		if (version == 3){
			//specifies a  expiration time, this is just missing in v4
			int offsetExpirationTime = offsetPubKeyType;
			writeExpirationTime(expirationTime,offsetExpirationTime);
			offsetPubKeyType += 2;
			
			print("writing offsetExpirationTime ");
			printwholePacket();
		}
		
		writeKeyType(keyType,offsetPubKeyType);//sets keyType byte
		print("writing keytype ");
		printwholePacket();
		int offsetMPIs = offsetPubKeyType + 1;
		writeMPIs(keyType,mpis,offsetMPIs); // sets keyData byte[]
		print("writing mpis ");
		printwholePacket();
		if (version == 3){
			calcFingerprintv3(keyType,mpis);//and keyid
		}
		else if (version == 4){
			calcFingerprintv4(); //and keyid
		}
	}
	private void calcFingerprintv3(PubKeyAlgos keyType,MPI[] mpis) {//TODO test me
		if ( keyType == PubKeyAlgos.RSA_ENC_OR_SIGN || keyType == PubKeyAlgos.RSA_ENC || keyType == PubKeyAlgos.RSA_SIGN){
			byte[] mpiData = mpis[0].getWholeMPI();
			this.keyID[7] =  mpiData[mpiData.length];
			this.keyID[6] =  mpiData[mpiData.length-1];
			this.keyID[5] =  mpiData[mpiData.length-2];
			this.keyID[4] =  mpiData[mpiData.length-3];
			this.keyID[3] =  mpiData[mpiData.length-4];
			this.keyID[2] =  mpiData[mpiData.length-5];
			this.keyID[1] =  mpiData[mpiData.length-6];
			this.keyID[0] =  mpiData[mpiData.length-7];
			MPI n = mpis[0];
			MPI e = mpis[1];
			
			byte[] toBeHashed = new byte[n.getDataSizeBytes()+e.getDataSizeBytes()];
			System.arraycopy(n.getWholeMPI(), 0, toBeHashed, 0, n.getDataSizeBytes());
			System.arraycopy(e.getWholeMPI(), 0, toBeHashed, n.getDataSizeBytes(), e.getDataSizeBytes());
			
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance("MD5");
			} catch (NoSuchAlgorithmException e2) {
				System.err.println("typo in pubkeypacket calcFingerprintv3");
				e2.printStackTrace();
			}
			this.fingerprint = md.digest(toBeHashed);
		}
		else{
			System.err.println("fingerprint calculation for rsa only");
		}		
	}

	public byte[] getFingerprint(){
		return this.fingerprint;
	}
	
	public void setFingerprint(byte[] finger){
		this.fingerprint = finger;
		System.arraycopy(this.fingerprint, 20-8, this.keyID, 0, 8);
	}
	public byte[] getKeyID(){
		return this.keyID;
	}	
	/*
	 * yet another attempt
	 */
	private void calcFingerprintv43(){
		ArrayList<Byte> data = new ArrayList<Byte>();
		
		data.add((byte) this.version);
		data.add(time[0]);
		data.add(time[1]);
		data.add(time[2]);
		data.add(time[3]);
		data.add(this.pubKeyAlgo.getNum());
		
		MPI tmp = null;
		for (int i=0; i< this.mpis.length;i++){
			tmp = mpis[i];
			for(int j=0; j<tmp.getSizeBytes();j++){
				data.add(tmp.getWholeMPI()[j]);
			}
		}
		
		byte[] dat= new byte[data.size()];
		for(int i=0; i<dat.length;i++){
			dat[i] = data.get(i);
		}
		//System.out.println(Util.ByteArr2String(dat));
		try {
			MessageDigest   digest = MessageDigest.getInstance("SHA1");
			
			digest.update((byte)0x99);
            digest.update((byte)(dat.length >> 8));
            digest.update((byte) dat.length);
            digest.update(dat);
            
            System.out.println(Util.ByteArr2String(digest.digest()));
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		
	}
	/*
	 * copied from org.bouncycastle.openpgp.PGPPublicKey
	 * TODO FIXME gpg --list-packets  pubkey2.gpg tells a different fingerprint
	 */
	private void calcFingerprintv4(){
		byte[] kBytes = new byte[wholePacket.length - head.getLength()];
		System.arraycopy(wholePacket, head.getLength(), kBytes, 0, wholePacket.length-head.getLength());
		System.out.print("kBytes  ");Util.printByteArr(kBytes);
		System.out.println("kBytes length  "+kBytes.length);
		System.out.println("kBytes version  "+kBytes[0]);
		System.out.println("kBytes time1  "+kBytes[1]);
		System.out.println("kBytes time1  "+kBytes[2]);
		System.out.println("kBytes time1  "+kBytes[3]);
		System.out.println("kBytes time4  "+kBytes[4]);
		System.out.println("kBytes algo  "+kBytes[5]);
		System.out.println("kBytes e length  "+kBytes[6]);
		System.out.println("kBytes e length   "+kBytes[7]);
		System.out.println("kBytes length  "+kBytes.length);
		
		try {
			MessageDigest md = MessageDigest.getInstance("SHA1");
			md.update((byte) 0x99);
			md.update((byte) (kBytes.length >>8));
			md.update((byte) kBytes.length );
			md.update(kBytes);
			
			this.fingerprint = md.digest();
			System.arraycopy(this.fingerprint, 20-8, this.keyID, 0, 8);//key id are the low 8 bytes of the fingerprint
			
		} catch (NoSuchAlgorithmException e) {
			System.err.println("typo in pubkeypacket calcFingerprint");
			e.printStackTrace();
		}
		System.out.print("fingerprint  ");Util.printByteArr(fingerprint);
		System.out.print("keyid                                            ");Util.printByteArr(this.keyID);
	}
	/*
	 * https://tools.ietf.org/html/rfc4880#section-12.2
	 * FIXME: fails, is different to the key id generation of the command gpg --list-packets  pubkey2.gpg
	 */
	private void calcFingerprintv42(){
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("typo in pubkeypacket calcFingerprint");
			e.printStackTrace();
		}
		byte[] toBeHashed = new byte[wholePacket.length - head.getLength() +3];//+3 for 0x99 + 2 octets length 
		Scalar scal = new Scalar(wholePacket.length - head.getLength(),2); // calc 2 octet length
		/*
		 * A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
   followed by the two-octet packet length, followed by the entire
   Public-Key packet starting with the version field.  The Key ID is the
   low-order 64 bits of the fingerprint.  Here are the fields of the
   hash material, with the example of a DSA key:
		 */
		toBeHashed[0] = (byte) 0x99;
		toBeHashed[1] = (byte) scal.getWholeScalar()[0];
		toBeHashed[2] = (byte) scal.getWholeScalar()[1];
		
		System.arraycopy(wholePacket, head.getLength(), toBeHashed, 3, wholePacket.length - head.getLength());//3: pos 0,1,2 are already written at
		//System.out.print("packet data     ");Util.printByteArr(wholePacket);
		//System.out.print("to be hashed ");Util.printByteArr(toBeHashed);
		
		byte[] hashed = md.digest(toBeHashed);
		
		//System.out.print("hashed       ");Util.printByteArr(hashed);
		this.fingerprint = hashed;
		System.arraycopy(this.fingerprint, 20-8, this.keyID, 0, 8);//key id are the low 8 bytes of the fingerprint
		//System.out.print("fingerprint  ");Util.printByteArr(fingerprint);
		//System.out.print("keyid                                            ");Util.printByteArr(this.keyID);
	}

	
	private void writeHeader(Header head) {
		System.arraycopy(head.getWholeHeader(), 0, this.wholePacket, 0, head.getLength());
	}

	private void writeExpirationTime(byte[] expirationTime, int offsetExpirationTime) {
		if (expirationTime.length !=2){
			System.err.println("invalid number of bytes in expiration Type for a v3 PubkeyPacket specified");
			System.exit(0);
		}
		System.arraycopy(expirationTime, 0, this.wholePacket, offsetExpirationTime, 2);
	}

	private void writeCreationTime(byte[] time, int offsetCreationTime) {
		System.arraycopy(time, 0, this.wholePacket, offsetCreationTime, 4);	
	}

	private int calculatePacketSize(int version, MPI[] mpis){
		int len = 0;
		/*
		 * first add static sizes
		 */
		if (version == 3){
			len += 1; //verion number
			len += 4; //time creation
			len += 2; // time expiration
			len += 1; // type pubKey algorithm
		}
		else if (version == 4){
			len += 1; //verion number
			len += 4; //time creation
			len += 1; // type pubKey algorithm
		}
		/*
		 * then add the size of the mpis
		 */
		for (int i=0; i<mpis.length;i++){
			len += mpis[i].getSizeBytes();
		}
		
		return len;
	}
	
	private void writeKeyType(PubKeyAlgos keyType, int offsetKeyType) {
		wholePacket[offsetKeyType] =  keyType.getNum();		
	}

	/*
	 * check if the correct number of MPIs is specified for this particular keytype
	 * int offsetMPIs is the offset in bytes from the beginning of the packet
	 */
	private void writeMPIs(PubKeyAlgos keyType, MPI[] mpis, int offsetMPIs){
		/*
		 * first check if the right amount of  MPIs are provided
		 */
		switch (keyType){
		case RSA_ENC_OR_SIGN:
		case RSA_ENC:
		case RSA_SIGN:// 2 MPIs n,e
			if (mpis.length != 2){
				System.err.print("an RSA PubKeyPacket needs 2 MPIs on construction");
			}
			writeMPI(mpis,offsetMPIs);
			break;
		case DSA:     // 4 MPIs p,q,g,y
			if (mpis.length != 4){
				System.err.print("an DSA PubKeyPacket needs 4 MPIs on construction");
			}
			writeMPI(mpis,offsetMPIs);
			break;
		case ELGAMAL: // 3 MPIs p,q,y
			if (mpis.length != 3){
				System.err.print("an ELGAMAL PubKeyPacket needs 3 MPIs on construction");
			}
			writeMPI(mpis,offsetMPIs);
			break;
		default:
			System.err.println("the keyType "+keyType.toString()+"is not implemented yet. Exxisting now");
			System.exit(0);
		}
	}
	
	/*
	 * set keyData, whole byte array
	 */
	private void writeMPI(MPI[] mpis, int offsetMPIs){
		int numMPIs = mpis.length; // number of MPIs
		int lenNewKeyData = 0;
		
		
		for (int i=0; i<numMPIs; i++){
			lenNewKeyData += mpis[i].getSizeBytes();
		}
		
		keyData = new byte[lenNewKeyData];
		
		/*
		 * copy all mpis into the newKeyData byte array
		 */
		
		int destPos = 0;
		
		for (int i=0; i<numMPIs; i++){
			System.arraycopy(mpis[i].getWholeMPI(), 0, keyData, destPos, mpis[i].getSizeBytes());
			destPos += mpis[i].getSizeBytes();
		}
		
		System.arraycopy(keyData, 0, wholePacket, offsetMPIs, keyData.length );
		
	}

	private void setVersion(int version){
		if (version != 3 && version != 4){
			System.err.println("wrong PubKeyPacket version specified");
			System.exit(0);
		}
		
		this.version = version;
	}
	
	private void writeVersion(int version, int offset){
		wholePacket[offset] = (byte) version;
	}
	
 	public int getVersion() {
		return version;
	}
	
	public byte[] readWholePacket(){
		return this.wholePacket;
	}
	public int readLen(){
		return this.wholePacket.length;
	}
	
	public long getWholePacketSize(){
		return this.wholePacket.length;
	}
}
