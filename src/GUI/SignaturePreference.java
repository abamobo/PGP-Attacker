package GUI;

import java.util.ArrayList;

import src.HashAlgorithms;
import src.MPI;
import src.PubKeyAlgos;
import src.SigSubTypes;
import src.SignatureSubPacket;

/*
 * for rsa signatures
 */
public class SignaturePreference{
	private ArrayList<SubPacketMetaData> hashedSubPackets = new ArrayList<SubPacketMetaData>();
	private ArrayList<SubPacketMetaData> UNhashedSubPackets = new ArrayList<SubPacketMetaData>();
	
	private HashAlgorithms hashAlgo = null;
	private PubKeyAlgos pubKeyAlgo = PubKeyAlgos.RSA_ENC_OR_SIGN;
	
	SignaturePreference(){
		this.hashAlgo = HashAlgorithms.SHA1;
	}
	
	/*SignaturePreference(ArrayList<SubPacketMetaData> hashedSubPackets,
			  			ArrayList<SubPacketMetaData> UNhashedSubPackets,
			  			HashAlgorithms hashAlgo){
		
		this.hashAlgo = hashAlgo;
		this.hashedSubPackets = hashedSubPackets;
		this.UNhashedSubPackets = UNhashedSubPackets;
	}*/
	public ArrayList<SubPacketMetaData> getHashedSubPackets() {
		return hashedSubPackets;
	}
	public void setHashedSubPackets(ArrayList<SubPacketMetaData> hashedSubPackets) {
		this.hashedSubPackets = hashedSubPackets;
	}
	public ArrayList<SubPacketMetaData> getUNhashedSubPackets() {
		return UNhashedSubPackets;
	}
	public void setUNhashedSubPackets(ArrayList<SubPacketMetaData> uNhashedSubPackets) {
		UNhashedSubPackets = uNhashedSubPackets;
	}
	public HashAlgorithms getHashAlgo() {
		return hashAlgo;
	}
	public PubKeyAlgos getPubKeyAlgo() {
		return pubKeyAlgo;
	}
	public void setHashAlgo(HashAlgorithms hashAlgo) {
		this.hashAlgo = hashAlgo;
	}	
	public boolean isHashedCapableOfHoldingPayload(int i){
		switch (hashedSubPackets.get(i).getSigSubType()){
		case PREFERRED_KEY_SERVER:
		case REGULAR_EXPRESSION:
		case SIGNERS_USER_ID:
		case NOTATION_DATA:
		case POLICY_URI:
			return true;	
		}
		
		return false;
	}
	public boolean isUnhashedCapableOfHoldingPayload(int i){
		switch (hashedSubPackets.get(i).getSigSubType()){
		case PREFERRED_KEY_SERVER:
		case REGULAR_EXPRESSION:
		case SIGNERS_USER_ID:
		case NOTATION_DATA:
		case POLICY_URI:
			return true;	
		}
		
		return false;
	}
}

class SubPacketMetaData{
	private boolean isUnhashedData = false;
	private SigSubTypes sigSubType = null;
	private boolean insertPayload = false;
	
	SubPacketMetaData(SigSubTypes sigSubType, boolean isUnhashed, boolean insertPayload){
		this.setUnhashedData(isUnhashed);
		this.insertPayload = insertPayload;
		this.sigSubType = sigSubType;
	}
	public boolean isPayloadInserted(){
		return this.insertPayload;
	}
	public void setIsPayloadInserted(){
		this.insertPayload = true;
	}
	public void setIsNOTPayloadInserted(){
		this.insertPayload = false;
	}
	public boolean isUnhashedData() {
		return isUnhashedData;
	}

	public void setUnhashedData(boolean isUnhashedData) {
		this.isUnhashedData = isUnhashedData;
	}
	
	public void addSubpacket(SigSubTypes type){
		this.sigSubType = type;
	}
	public SigSubTypes getSigSubType(){
		return this.sigSubType;
	}
	
}