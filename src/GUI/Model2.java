package GUI;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

import src.*;
/*
 * uses singelton
 * PubKeyPacket is added on instantiation
 * TODO: add revokation
 * TODO: add subkey
 * TODO : add subkey revok
 * 
 */
public class Model2 {
	
	private static Model2 instance = null;
	
	private PubKeyPacket pubKey = null;
	private ArrayList<SignaturePacket> pubKeyRevokations = new ArrayList<SignaturePacket>();
	
	private ArrayList<UserIDPacket> userIDs = new ArrayList<UserIDPacket>();
	private ArrayList<SignaturePacket> userIDSigs = new ArrayList<SignaturePacket>();

	private ArrayList<UserAttributePacket> userAttrs = new ArrayList<UserAttributePacket>();
	private ArrayList<SignaturePacket> userAttrSigs = new ArrayList<SignaturePacket>();
	
	private ArrayList<SubKeyPacket> subKeys = new ArrayList<SubKeyPacket>();
	private ArrayList<SignaturePacket> subKeyRevokations = new ArrayList<SignaturePacket>();
	
	private String payload = null;
	
	
	private final Path path = Paths.get(System.getProperty("user.dir"), "PubKey.gpg"); // current work dir of the executable
	
	public ArrayList<SignaturePacket> getPubKeyRevokations(){
		return pubKeyRevokations;
	}
	public ArrayList<UserIDPacket> getUserIDs(){
		return userIDs;
	}
	public ArrayList<SignaturePacket> getUserIDSigs(){
		return userIDSigs;
	}
	public ArrayList<UserAttributePacket> getUserAttrs(){
		return userAttrs;
	}
	public ArrayList<SignaturePacket> getUserAttrSigs(){
		return userAttrSigs;
	}
	public ArrayList<SubKeyPacket> getSubKeys(){
		return subKeys;
	}
	public ArrayList<SignaturePacket> getSubKeyRevokations(){
		return subKeyRevokations;
	}
	
	public SignaturePacket getPubKeyRevokation(int num){
		return pubKeyRevokations.get(num);
	}
	public UserIDPacket getUserID(int num){
		return userIDs.get(num);
	}
	public SignaturePacket getUserIDSig(int num){
		return userIDSigs.get(num);
	}
	public UserAttributePacket getUserAttr(int num){
		return userAttrs.get(num);
	}
	public SignaturePacket getUserAttrSig(int num){
		return userAttrSigs.get(num);
	}
	public SubKeyPacket getSubKey(int num){
		return subKeys.get(num);
	}
	public SignaturePacket getSubKeyRevokation(int num){
		return subKeyRevokations.get(num);
	}
	
	
	
	/*
	 * return the number of packets in an arraylist
	 */
	public int getNumPubKeyRevokations(){
		return pubKeyRevokations.size();
	}
	public int getNumUserIDs(){
		return userIDs.size();
	}
	public int getNumUserIDSigs(){
		return userIDSigs.size();
	}
	public int getNumUserAttrs(){
		return userAttrs.size();
	}
	public int getNumUserAttrSigs(){
		return userAttrSigs.size();
	}
	public int getNumSubKeys(){
		return subKeys.size();
	}
	public int getNumSubKeyRevokations(){
		return subKeyRevokations.size();
	}
	
	
	
	
	
	/*
	 * gets the standard Payload
	 */
	public String getStandardPayload(){
		return this.payload;
	}
	/*
	 * returns the publick key instance
	 */
	public PubKeyPacket getPubKey(){
		return this.pubKey;
	}
	
	/*
	 * adds an user id, as well as its signature to the list
	 */
	public void addUserID(boolean customPayload, String payload, SignaturePreference sigPrefs){
		if (customPayload){
			UserIDPacket userid = new UserIDPacket(Util.payload2Barr(payload));
			userIDs.add(userid);
			userIDSigs.add(new SignaturePacket(4,
												SignatureTypes.POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET,
												PubKeyAlgos.RSA_ENC_OR_SIGN,
												sigPrefs.getHashAlgo(),
												sigPrefs.getHashedSubPackets(),
												sigPrefs.getUNhashedSubPackets(),
												Util.payload2Barr(payload),
												userid,
												pubKey
												));
		}
		else{
			UserIDPacket userid = new UserIDPacket(this.payload);
			userIDs.add(userid);
			userIDSigs.add(new SignaturePacket(4,
												SignatureTypes.POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET,
												PubKeyAlgos.RSA_ENC_OR_SIGN,
												sigPrefs.getHashAlgo(),
												sigPrefs.getHashedSubPackets(),
												sigPrefs.getUNhashedSubPackets(),
												Util.payload2Barr(this.payload),
												userid,
												pubKey
												));
		}		
	}
	/*
	 * adds an user attribute, as well as its signature to the list
	 */
	public void addUserAttr(boolean customPayload, String payload, SignaturePreference sigPrefs){
		if (customPayload){
			UserAttributePacket userattr = new UserAttributePacket(Util.payload2Barr(payload),customPayload);
			userAttrs.add(userattr);
			userAttrSigs.add(new SignaturePacket(4,
												SignatureTypes.POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET,
												PubKeyAlgos.RSA_ENC_OR_SIGN,
												sigPrefs.getHashAlgo(),
												sigPrefs.getHashedSubPackets(),
												sigPrefs.getUNhashedSubPackets(),
												Util.payload2Barr(payload),
												userattr,
												pubKey
												));
		}
		else{
			UserAttributePacket userattr = new UserAttributePacket(this.payload,customPayload);
			userAttrs.add(userattr);
			userAttrSigs.add(new SignaturePacket(4,
												SignatureTypes.POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET,
												PubKeyAlgos.RSA_ENC_OR_SIGN,
												sigPrefs.getHashAlgo(),
												sigPrefs.getHashedSubPackets(),
												sigPrefs.getUNhashedSubPackets(),
												Util.payload2Barr(this.payload),
												userattr,
												pubKey
												));
		}		
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	public void writeAll(){
		
		/*
		 * init FileUtils
		 */
		FileUtil fu = new FileUtil(this.path);
		fu.createFile();
		
		/*
		 * 1. write public Key itself
		 */
		fu.AppendChunk(pubKey.getWholePacket());
		/*
		 * 2. write revocation signature
		 */
		for (int i=0; i<pubKeyRevokations.size();i++){
			fu.AppendChunk(pubKeyRevokations.get(i).getWholePacket());
		}
		/*
		 * 3. write all userIDs and their Signatures
		 */
		for (int i=0; i< userIDs.size(); i++){
			fu.AppendChunk(userIDs.get(i).getWholePacket());
			fu.AppendChunk(userIDSigs.get(i).getWholePacket());
		}
		/*
		 * 4. write all userAttributes and their Signatures
		 */
		for (int i=0; i< userAttrs.size(); i++){
			fu.AppendChunk(userAttrs.get(i).getWholePacket());
			fu.AppendChunk(userAttrSigs.get(i).getWholePacket());
		}
		
		/*
		 * 5. write subkeys and their revokation signatures (can be differently big arraylists
		 * 	
		 */
		for (int i=0; i< subKeys.size(); i++){
			fu.AppendChunk(subKeys.get(i).getWholePacket());
		}
		for (int i=0; i< subKeyRevokations.size(); i++){
			fu.AppendChunk(subKeyRevokations.get(i).getWholePacket());
		}
	}
	
	
	
	
	private Model2(){
		
		/*
		 * generate new public key
		 */
		/*
		 * mpis for pubkeypacket
		 */
		MPI n,e;
		
		byte[] data = new byte[256];//generate a 2048 bit modulus for RSA
		data[0] = (byte) 0xFF;//n= 0xFF 00 00 00 ...
		
		n = new MPI(data);
		
		data = new byte[1];
		data[0] = (byte) 0x01; // set e 0x01
		
		e = new MPI(data);
		
		MPI[] mpis = new MPI[2];
		mpis[0] = n;
		mpis[1] = e;
		
		byte[] time = {0x01,0x02,0x03,0x04};
		byte[] expTime={1,2};
		pubKey = new PubKeyPacket(PubKeyAlgos.RSA_ENC_OR_SIGN,4,mpis,time,expTime);
		// end create pubkey
		
		//begin read payload in
		//TODO:  change to real payload
		this.payload = "asdfasdf";
		//this.payload = Util.readPayloads();
		
	}
	
	public static Model2 getInstance(){
		if (instance == null){
			instance = new Model2();
		}
		return instance;
	}
	
	
}
