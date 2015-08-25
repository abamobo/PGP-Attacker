package GUI;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import src.SigSubTypes;

public class Model {

	private ArrayList<Entry> entries = new ArrayList<Entry>();
	//private GeneratorEntry genEntry = new GeneratorEntry(); // has always to be last entry in entries
	private int numOfPubKeys = 0;
	private boolean isFirstUserIDAdded = false;
	private boolean isFirstSubKeyAdded = false;
	private boolean isFirstUserAttrAdded = false;
	private boolean isPubKeyAdded = false;;
	private boolean isFirstSubKeyRevAdded = false;
	
	private boolean isRemovedOptionUsed = false;//we have to do some clean up
	
	private int lastNotSignaturePacket = 0;
	
	private static Model instance = null;
	
	public static Model getInstance(){
		if (instance == null){
			instance = new Model();
		}
		return instance;
	}
	
	public ArrayList<Entry> getEntries(){
		return this.entries;
	}
	public Entry getEntry(int i){
		return this.entries.get(i);
	}
	public int getNumOfEntries(){
		return this.entries.size();
	}
	
	public void addEntry(Entry entry){
		entries.add(entry);
	}
	public void changeEntry(Entry entry,int pos){
		entries.set(pos, entry);
	}
	public void removeLastEntry(){
		if (entries.size() > 0){
			entries.remove(entries.size()-1);
		}
		else{
		System.err.println("last entry cannot be removed, since there are no entries ");
		}
	}
	
	
	
	public void addPubKey(){
		if(numOfPubKeys == 0){
			entries.add(new Entry(KindOfEntry.PubKey,"Public Key",0));
		}
		else{
			System.err.println("a pubkey is already present");
		}
		this.lastNotSignaturePacket = this.getNumOfLastEntry();
		numOfPubKeys++;
		this.setPubKeyAdded(true);
	}
	public void addSubKey(){
		
		entries.add(new Entry(KindOfEntry.SubKey,"Sub Key",1));
		
		this.isFirstSubKeyAdded = true;
		this.lastNotSignaturePacket = this.getNumOfLastEntry();
	}
	/*
	 * always indented by one
	 */
	public void addUserIdEntry(){
		Entry entry = new Entry(KindOfEntry.UserID,"User Id", 1);
		entries.add(entry);
		this.isFirstUserIDAdded = true;
		this.lastNotSignaturePacket = this.getNumOfLastEntry();
	}
	/*
	 * always indented by one
	 */
	public void addUserAttrEntry() {
		Entry entry = new Entry(KindOfEntry.UserAttr,"User Attribute", 1);
		
		entries.add(entry);
		this.isFirstUserAttrAdded = true;
		this.lastNotSignaturePacket = this.getNumOfLastEntry();
	}
	/*
	 * never indented by one
	 */
	public void addTextEntry(String text, int numOfIndents){
		entries.add(new Entry(KindOfEntry.Text, text,numOfIndents));
	}
	
	/*
	 * belongs to marks the 
	 */
	public void addHashedSigSubEntry(SigSubTypes sigSubType, int belongsTo){
		Entry entry = new Entry(KindOfEntry.hashedSubPacket,sigSubType.toString(),7);
		entry.setSigSubType(sigSubType);
		entry.setWhichSignatureBelongsThisTo(belongsTo);
		entries.add(entry);
	}
	public void addUnhashedSigSubEntry(SigSubTypes sigSubType,int belongsTo){
		Entry entry = new Entry(KindOfEntry.UnhashedSubPacket,sigSubType.toString(),7);
		entry.setSigSubType(sigSubType);
		entry.setWhichSignatureBelongsThisTo(belongsTo);
		entries.add(entry);
	}
	/*public void addHashedSigSubEntry( int belongsTo){
		Entry entry = new Entry(KindOfEntry.hashedSubPacket,3);
		entry.setWhichSignatureBelongsThisTo(belongsTo);
		entries.add(entry);
	}
	public void addUnhashedSigSubEntry(int belongsTo){
		Entry entry = new Entry(KindOfEntry.UnhashedSubPacket,3);
		entry.setWhichSignatureBelongsThisTo(belongsTo);
		entries.add(entry);
	}*/
	/*
	 * always indented by 2
	 */
	public void addSignatureEntry(int whichPacketIs2BeSigned){
		KindOfEntry type = null;
		Entry entry = null;
		switch(entries.get(whichPacketIs2BeSigned).getType()){
		case Text:
			System.err.println(" a text entry cannot be signed");
			return;
		case PubKey:
			type = KindOfEntry.SigRevPubKey;
			entry = new Entry(type,"Revokation Signature of the Pub Key",2);
			break;
		case SubKey:
			type = KindOfEntry.SigRevSubKey;
			 entry = new Entry(type,"Revokation Signature of a Sub Key Packet",2);
			this.isFirstSubKeyRevAdded =true;
			break;
		case UserID:
			type = KindOfEntry.SigUserID;
			 entry = new Entry(type,"Signature of a User Id Packet",2);
			break;
		case UserAttr:
			type = KindOfEntry.SigUserAttr;
			 entry = new Entry(type,"Signature of a User Attribute Packet",2);
			break;
		case SigUserID:
		case SigUserAttr:
		case SigRevPubKey:
		case SigRevSubKey:
			System.err.println("signatures are not to bsigned again");
			return;	
		}
		
		entry.setWhichPacketis2beSigned(whichPacketIs2BeSigned);
		

		entries.add(entry);
	}
	public void addSignatureEntry2(SignaturePreference sigPref, int whichPacketIs2BeSigned){
		KindOfEntry type = null;
		Entry entry = null;
		switch(entries.get(whichPacketIs2BeSigned).getType()){
		case Text:
			System.err.println(" a text entry cannot be signed");
			return;
		case PubKey:
			type = KindOfEntry.SigRevPubKey;
			entry = new Entry(type,"Revokation Signature of the Pub Key",2);
			break;
		case SubKey:
			type = KindOfEntry.SigRevSubKey;
			 entry = new Entry(type,"Revokation Signature of a Sub Key Packet",2);
			break;
		case UserID:
			type = KindOfEntry.SigUserID;
			 entry = new Entry(type,"Signature of a User Id Packet",2);
			break;
		case UserAttr:
			type = KindOfEntry.SigUserAttr;
			 entry = new Entry(type,"Signature of a User Attribute Packet",2);
			break;
		case SigUserID:
		case SigUserAttr:
		case SigRevPubKey:
		case SigRevSubKey:
			System.err.println("signatures are not to bsigned again");
			return;	
		}
		entry.setWhichPacketis2beSigned(whichPacketIs2BeSigned);
		//entry.setSigPref(sigPref);//TODO maybe change

		entries.add(entry);
		/*
		 * 
		Entry entry = new Entry(KindOfEntry.hashedSubPacket,sigSubType.toString(),7);
		 */
		int numSig = getNumOfLastEntry();
		entries.add(new Entry(KindOfEntry.Text,"hashed Subpackets:",3));
		for (int i=0; i<sigPref.getHashedSubPackets().size(); i++){
			if (sigPref.isHashedCapableOfHoldingPayload(i)){
				entry = new Entry (KindOfEntry.hashedSubPacket,sigPref.getHashedSubPackets().get(i).getSigSubType().toString(), 7);
				entry.setWhichSignatureBelongsThisTo(numSig);
				entries.add(entry);
			}
		}
		entries.add(new Entry(KindOfEntry.Text,"unhashed Subpackets:",3));
		for (int i=0; i<sigPref.getUNhashedSubPackets().size(); i++){
			if (sigPref.isUnhashedCapableOfHoldingPayload(i)){
				entry = new Entry (KindOfEntry.UnhashedSubPacket,sigPref.getUNhashedSubPackets().get(i).getSigSubType().toString(), 7);
				entry.setWhichSignatureBelongsThisTo(numSig);
				entries.add(entry);	
			}
		}
	}
	
	/*
	 * call this method after the generate button is hit, to check if
	 * all neccessary information is provided
	 * 
	 */
	public boolean checkAll(){
		for ( int i=0; i<entries.size(); i++){
			Entry  entry = entries.get(i);
			
			switch (entry.getType()){
			case Text:
				
				break;
			case PubKey:
			case SubKey:
				
				break;
			case UserID:
			case UserAttr:
				
				break;
			case SigUserID:
			case SigUserAttr:
			case SigRevPubKey:
			case SigRevSubKey:
				if (entry.getWhichPacketis2beSigned() == 0){ //defautl value and points to pubkey
					System.err.println("the pubkey can not be signed, probvably forgot to set which packet is to besigned");
					return false;
				}
				
			/*	if (entry.getSigPref() == null){
					System.err.println("sigPref for signature "+i+ " is missing, which signs "+entry.getWhichPacketis2beSigned());
					return false;
				}*/
				
				Entry entry2BeSigned = entries.get(entry.getWhichPacketis2beSigned());
				/*
				 * TODO: typcheck on entry to be signed
				 */
				
				
				break;
			case hashedSubPacket:
			case UnhashedSubPacket:
				break;
			default:
				System.err.println("checkall model.java should not happend");
			}
			
		}
		
		return true;
	}

	public void clear(JPView jpView) {
		numOfPubKeys = 0;
		jpView.removeEntriesFromView(getInstance()); // clear view
		entries  = new ArrayList<Entry>();
	}

	public int getNumOfLastEntry(){
		return this.entries.size()-1;
	}

	public boolean isFirstUserAttrAdded() {
		return isFirstUserAttrAdded;
	}
	
	public boolean isFirstSubKeyAdded() {
		return isFirstSubKeyAdded;
	}
	
	public boolean isFirstUserIDAdded() {
		return isFirstUserIDAdded;
	}
	
	public boolean isPubKeyAdded() {
		return isPubKeyAdded;
	}
	public void setPubKeyAdded(boolean isPubKeyAdded) {
		this.isPubKeyAdded = isPubKeyAdded;
	}

	public boolean isFirstSubKeyRevAdded() {
		return isFirstSubKeyRevAdded;
	}
	
	public boolean isRemovedOptionUsed() {
		return isRemovedOptionUsed;
	}

	public void setRemovedOptionUsed(boolean isRemovedOptionUsed) {
		this.isRemovedOptionUsed = isRemovedOptionUsed;
	}

	public void setSubKeyRevAdded(boolean b) {
		this.isFirstSubKeyRevAdded = b;
		
	}

	public void setFirstUserIDAdded(boolean b) {
		this.isFirstUserIDAdded = b;
		
	}

	public void setFirstUserAttrAdded(boolean b) {
		this.isFirstUserAttrAdded = b;
	}

	public void setFirstSubKeyAdded(boolean b) {
		this.isFirstSubKeyAdded = b;
	}

	public int getLastNotSignaturePacket() {
		return lastNotSignaturePacket;
	}

	public void setLastNotSignaturePacket(int lastNotSignaturePacket) {
		this.lastNotSignaturePacket = lastNotSignaturePacket;
	}


}




enum KindOfEntry{
	PubKey,
	SubKey,
	UserID,
	UserAttr,
	SigUserID,
	SigUserAttr,
	SigRevPubKey,
	SigRevSubKey,
	Text,
	hashedSubPacket,
	UnhashedSubPacket
}
/*
 * the idea:
 * the user can change the list of entries via the view, onn hitting the generate button the trafo classs uses the model class to create the actual packets
 * the model contains just the data needed to create the different packets
 * 
 * 
 * if type = pubkey,subkey: no further arguments are needed
 * if type = text: a String text has to be supplied
 * if type = userid,userattr: parameters needed: userwantscustomPayload? cutom payload
 * if type = signature: sigPref,custompayload, iscustompayload, and which packet is to be signed
 * 
 * 
 * optional the function call indent, indents the whole entry by 10
 */
class Entry extends JPanel{
	
	private KindOfEntry type = null;
	private String text = null; // only used for plain text entries
	private int numOfIndents = 0;
	
	//signature packet
	//private SignaturePreference sigPref = null;
	private int whichPacketis2beSigned = 0;
	//signaturesubpacket
	private int whichSignatureBelongsThisTo = 0;
	
	/*custom payload is for later
	 * 
	 */
//	private String customPayload;
//	private boolean isCustomPayload;
	
	private JCheckBox cbField = null; // checkbox 
	private SigSubTypes sigSubType;
	
	/*
	 * this constructor is unviversal, mainly it can be used for for pubkey,subkey
	 * however, since at the creating of the entry, some parameters cannot be known there 
	 * is a check, which packet data will behold 
	 */
	/*Entry(KindOfEntry type, int numOfIndents){
		this.type = type;
		this.numOfIndents = numOfIndents;
		this.setLayout(new BoxLayout(this,BoxLayout.X_AXIS));
		
		this.add(Box.createRigidArea(new Dimension(10*numOfIndents,0)));
		this.cbField = new JCheckBox(type.toString());
		cbField.setHorizontalAlignment(SwingConstants.LEFT);
		this.add(cbField);
		
		switch (type){
		case UserID:
		case UserAttr:
			//this.setCustomPayload(false);
			//this.customPayload = null;
			break;
		case SigUserID:
		case SigUserAttr:
		case SigRevPubKey:
		case SigRevSubKey:
			//this.setCustomPayload(false);
			//this.customPayload = null;
		//	this.sigPref = null;
			this.whichPacketis2beSigned = 0;
			this.remove(cbField);
			this.text = type.toString();
			break;
		case hashedSubPacket:
		case UnhashedSubPacket:
			
		}
		
		
		
	}*/
	public void setSigSubType(SigSubTypes sigSubType) {
		this.sigSubType = sigSubType;
		
	}
	public SigSubTypes getSigSubType(SigSubTypes sigSubType) {
		return this.sigSubType;
	}
	public String getText(){
		return this.text;
	}
	/*
	 * this constructor is for text
	 */
	Entry(KindOfEntry type, String text,int numOfIndents) {
		this.numOfIndents = numOfIndents;
		this.type = type;
		this.text = text;
		this.setLayout(new BoxLayout(this,BoxLayout.X_AXIS));
		
		if (type == KindOfEntry.UnhashedSubPacket || type == KindOfEntry.hashedSubPacket ||
				type == KindOfEntry.UserAttr || type == KindOfEntry.UserID){
			this.add(Box.createRigidArea(new Dimension(10*numOfIndents,0)));
			this.cbField = new JCheckBox(text);
			cbField.setHorizontalAlignment(SwingConstants.LEFT);
			this.add(cbField);
		}
	
	}
	
	/*public void updateText(String text){
		if (type == KindOfEntry.UnhashedSubPacket || type == KindOfEntry.hashedSubPacket){
			this.cbField = new JCheckBox();
		}
	}*/
	
	/*public String getCustomPayload() {
		return customPayload;
	}
	public void setCustomPayload(String cutomPayload) {
		this.customPayload = cutomPayload;
	}
	public boolean isCustomPayload() {
		return isCustomPayload;
	}
	public void setCustomPayload(boolean isCustomPayload) {
		this.isCustomPayload = isCustomPayload;
	}*/
/*	public SignaturePreference getSigPref() {

		if (this.type == KindOfEntry.SigUserID || this.type == KindOfEntry.SigUserAttr ||
			this.type == KindOfEntry.SigRevPubKey || this.type == KindOfEntry.SigRevSubKey){
			return sigPref;
		}
		else{
			System.err.println("a sigpref cannot be retruned, since this entry is not a signature, but a "+type.toString());
			return sigPref; // which is null
		}
		
	}
	public void setSigPref(SignaturePreference sigPref) {
		if (this.type == KindOfEntry.SigUserID || this.type == KindOfEntry.SigUserAttr ||
				this.type == KindOfEntry.SigRevPubKey || this.type == KindOfEntry.SigRevSubKey){
			this.sigPref = sigPref;
		}
		else{
			System.err.println("a sigpref cannot be set, since this entry is not a signature, but a "+type.toString());
			this.sigPref = null;
		}
	}*/
	public int getWhichPacketis2beSigned(){
		return this.whichPacketis2beSigned;
	}
	public void setWhichPacketis2beSigned(int num){
		this.whichPacketis2beSigned = num;
	}
	
	public void check(){
		if (this.cbField != null){//2. construcotr does not create an checkbox
			this.cbField.setSelected(true);
		}
	}
	public void unCheck(){
		if (this.cbField != null){
			this.cbField.setSelected(false);
		}
	}
	public boolean isChecked(){
		return this.cbField.isSelected();
	}
	public KindOfEntry getType(){
		return this.type;
	}
	
	/*
	 * 
	 * only interesting for text type
	 */
	@Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        if ( (this.type != KindOfEntry.UnhashedSubPacket && this.type != KindOfEntry.hashedSubPacket)      		
        		 && this.text != null){
			int fontSize = 15;
			g.setColor(Color.black);
		    g.setFont(new Font("Arial", Font.BOLD, fontSize));
			g.drawString(this.text, 20*this.numOfIndents, 15);
		}
    }
	public int getWhichSignatureBelongsThisTo() {
		return whichSignatureBelongsThisTo;
	}
	public void setWhichSignatureBelongsThisTo(int whichSignatureBelongsThisTo) {
		this.whichSignatureBelongsThisTo = whichSignatureBelongsThisTo;
	}
	
	
	
}




