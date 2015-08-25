package GUI;

import java.awt.Canvas;
import java.awt.Checkbox;
import java.awt.Color;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.Arrays;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import src.SigSubTypes;
import src.SignaturePacket;
import src.SignatureSubPacket;
import src.UserIDPacket;

/*
 * View
 */
public class JPView extends JPanel{
	
	private JButton jbCheckAll = new JButton("check all");
	private JButton jbUncheckAll = new JButton("uncheck all");
	
	private Checkbox cbUserID = new Checkbox("fill UserID");
	private Checkbox cbUserIDCustom = new Checkbox("custom payload?");
	private JTextField jtfUserIDCustomPayload = new JTextField("<>'\"");
	private GeneratorEntry genEntry;
	
	
	
	private Container contentPane;
	
	public GeneratorEntry getGenEntry(){
		return genEntry;
	}
	
	
	JPView(Container contentPane, Model model){
		this.contentPane = contentPane;
		this.setPreferredSize(new Dimension(contentPane.getWidth()-100,12000));//ugly
		this.setOpaque(true);

		this.setSize(this.getWidth(), 1);
		GridLayout grid = new GridLayout(500,1);	
		this.setLayout(grid);	
		
		
		
		genEntry  = new GeneratorEntry(model,this);
		this.add(genEntry);
	}
	

	
	
	/*
	 * use this function to update the view  depending on the model
	 * this will create for every packet, wehere data can be maniulated an entry
	 */
//	public void updateView(Model model) {
		//FIXME hier weitermachen
		/*
		 * 1.  write pubkey always first
		 */
	//	entries.add(new Entry("PubKey",1));
		
		
		
		 // then write revocation signatures if present
		 
		/*if (model.getNumPubKeyRevokations() > 0){
			entries.add(new Entry("Revokation Signatures:",entries.size()+1));
		
		
			for (int i= 0; i<model.getNumPubKeyRevokations(); i++){
				SignaturePacket sig = model.getPubKeyRevokation(i);
				entries.add(new Entry("Revokation Signature " + i+": ",entries.size()+1));
				
				if (sig.getNumHashedSubPacketsWhichCanHoldPayload() > 0){
					entries.add(new Entry("Revokation Signature " +i+" -  Hashed Subpackets",entries.size()+1,1));
					for(int j=0; j<sig.getNumHashedSubPackets(); j++){
						entries.add(new Entry(KindOfEntry.SigUserID,sig.getHashedSubpacket(j).getSigSubType().toString(),j,i,2));
					}
				}
				
				if (sig.getNumUnhashedSubPacketsWhichCanHoldPayload() > 0){
					entries.add(new Entry("Revokation Signatures " +i+" -  Unhashed Subpackets",entries.size()+1,1));
					for(int j=0; j<sig.getNumUnhashedSubPackets(); j++){
						entries.add(new Entry(KindOfEntry.SigUserID,sig.getUnhashedSubpacket(j).getSigSubType().toString(),j,i,2));
					}
				}
			}
		}		
		
		
		//then write user ID if present
		 
		if (model.getNumUserIDs() > 0){
			entries.add(new Entry("User IDs:",entries.size()+1));
				
			for (int i= 0; i<model.getNumUserIDs(); i++){
				entries.add(new Entry("User ID "+(i+1)+": ",entries.size()+1,1));
				
				entries.add(new Entry(KindOfEntry.UserID,"content",1,0,2));
			}
		}
		
		 // then write user ID signatures if present
		 
		if (model.getNumUserIDSigs() > 0){
			entries.add(new Entry("User ID Signatures:",entries.size()+1));
		
			for (int i= 0; i<model.getNumUserIDSigs(); i++){
				
				SignaturePacket sig = model.getUserIDSig(i);
				
				if (sig.getNumHashedSubPacketsWhichCanHoldPayload() > 0){
					entries.add(new Entry("User ID Signature " +(i+1)+" -  Hashed Subpackets",entries.size()+1,1));
					for(int j=0; j<sig.getNumHashedSubPackets(); j++){
						SignatureSubPacket sigSub = sig.getHashedSubpacket(j);
						if (sigSub.isCapableOfHoldingPayload()){
							entries.add(new Entry(KindOfEntry.SigUserID,sigSub.getSigSubType().toString(),j,i,2));
						}
					}
				}
				
				if (sig.getNumUnhashedSubPacketsWhichCanHoldPayload() > 0){
					entries.add(new Entry("User ID Signature " +(i+1)+" -  Unhashed Subpackets",entries.size()+1,1));
					for(int j=0; j<sig.getNumUnhashedSubPackets(); j++){
						SignatureSubPacket sigSub = sig.getUnhashedSubpacket(j);
						if (sigSub.isCapableOfHoldingPayload()){
							entries.add(new Entry(KindOfEntry.SigUserID,sigSub.getSigSubType().toString(),j,i,2));
						}
					}
				}
				
			}
		}
		
		
		 // _________________________________________________________________________________________________________________________-
		 
	
		
		 //then write user Attribute if present
		 
		if (model.getNumUserAttrs() > 0){
			entries.add(new Entry("User Attributes:",entries.size()+1));
		
		
			for (int i= 0; i<model.getNumUserAttrs(); i++){
				entries.add(new Entry("User Attribute "+(i+1)+": ",entries.size()+1,1));
				entries.add(new Entry(KindOfEntry.UserAttr,"content",1,0,2));
			}
		}
		
		// then write user Attribute signatures if present
		 
		if (model.getNumUserAttrSigs() > 0){
			entries.add(new Entry("User Attribute Signatures:",entries.size()+1));
		
				
			for (int i= 0; i<model.getNumUserAttrSigs(); i++){
				
				SignaturePacket sig = model.getUserAttrSig(i);
				
				if (sig.getNumHashedSubPacketsWhichCanHoldPayload() > 0){
					entries.add(new Entry("User Attribute Signature " +(i+1)+" -  Hashed Subpackets",entries.size()+1,1));
					for(int j=0; j<sig.getNumHashedSubPackets(); j++){
						SignatureSubPacket sigSub = sig.getHashedSubpacket(j);
						
						if (sigSub.isCapableOfHoldingPayload()){
							entries.add(new Entry(KindOfEntry.UserAttr,sigSub.getSigSubType().toString(),j,i,2));
						}
					}
				}
				
				if (sig.getNumUnhashedSubPacketsWhichCanHoldPayload() > 0){
					entries.add(new Entry("User Attribute Signature " +(i+1)+" -  Unhashed Subpackets",entries.size()+1,1));
					for(int j=0; j<sig.getNumUnhashedSubPackets(); j++){
						SignatureSubPacket sigSub = sig.getUnhashedSubpacket(j);
						if (sigSub.isCapableOfHoldingPayload()){
							entries.add(new Entry(KindOfEntry.UserAttr,sigSub.getSigSubType().toString(),j,i,2));
						}
					}
				}
				
			}
		
		}
		
		
		addEntries2View();
	}
	*/
	
	
	
	
	
	private void addEntries2View(Model model){
		this.remove(genEntry);
		for (int i=0; i<model.getNumOfEntries(); i++){
			this.add(model.getEntry(i));
		}
		
		
		this.revalidate();
		
	}
	
	public void removeEntriesFromView(Model model){
		for (int i=0; i<model.getNumOfEntries(); i++){
			this.remove((model.getEntry(i)));
		}
		this.revalidate();
	}




	public void updateView(Model model) {
		this.remove(genEntry);
		removeEntriesFromView(model);
		addEntries2View(model);
		this.add(genEntry);
		this.revalidate();
	}
	
}



class GeneratorEntry extends JPanel{
	private JComboBox job = new JComboBox();
	private JLabel jladd = new JLabel("choose new part");
	private JButton jbremove = new JButton("remove last");
	
	GeneratorEntry(Model model, JPView view){
		this.setBorder(BorderFactory.createLineBorder(Color.black));
		
		job.addActionListener(new NextPacketActionListener(model, view));
		
		this.setLayout(new BoxLayout(this,BoxLayout.X_AXIS));
		this.add(jladd);
		
		this.add(Box.createRigidArea(new Dimension(10,0)));
		
		String[] Strings = {"Public Key"};
		DefaultComboBoxModel m = new DefaultComboBoxModel(Strings);
		job.setModel(m);
		this.add(job);
		
		this.add(Box.createRigidArea(new Dimension(10,0)));
		
		jbremove.addActionListener(new RemoveLastActionListener(model,view));
		
		this.add(jbremove);
	}
	
	public void setComboBoxContent(String[] strings){
		if (job != null){
			this.remove(job);
		}
		DefaultComboBoxModel m = new DefaultComboBoxModel(strings);
		job.setModel(m);
		this.remove(jbremove);
		this.add(job);
		this.add(jbremove);
	}
	
}
class RemoveLastActionListener implements ActionListener{

	private Model model;
	private JPView view;

	public RemoveLastActionListener(Model model, JPView view) {
		this.model = model;
		this.view = view;
	}

	@Override
	public void actionPerformed(ActionEvent arg0) {
		view.removeEntriesFromView(model);
		model.removeLastEntry();
		
		model.setRemovedOptionUsed(true);
		view.updateView(model);
		
	}
	
}
class NextPacketActionListener implements ActionListener{
	/*
	 *  One Public-Key packet

     - Zero or more revocation signatures

     - One or more User ID packets

     - After each User ID packet, zero or more Signature packets
       (certifications)

     - Zero or more User Attribute packets

     - After each User Attribute packet, zero or more Signature packets
       (certifications)

     - Zero or more Subkey packets

     - After each Subkey packet, one Signature packet, plus optionally a
       revocation
	 */
	private Model model;
	private JPView view;
	private String[] stringsPubKey;
	private String[] stringsSigSubTypes;
	
	//following strings are used as boundaries between parts
	private String beginHashedSubPackets = "Hashed SubPackets";
	private String beginUnhashedSubPackets = "Unhashed Subpackets";
	private String endSignature = "";
	private int ctrLastSig = -1;
	
	//few more String constants
	private String userID = KindOfEntry.UserID.toString();//has to be done this way, in order to use the switch
	private String userAttr = KindOfEntry.UserAttr.toString();
	private String subKey = KindOfEntry.SubKey.toString();
	private String[] strings;
	
	
	//this is needed to know when main packets can be writeen again
	private boolean hasSigBegun = false;
	
	NextPacketActionListener(Model model, JPView view){
		this.view = view;
		this.model = model;	
		
		reconstructstringsSigSubTypes();
		
		
	}
	
	private void reconstructstringsSigSubTypes(){
		/*
		 * enum KindOfEntry{
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
		 */
		String[] stringsPubKey = {KindOfEntry.PubKey.toString()};
		this.stringsPubKey = stringsPubKey;
		
		this.strings = strings;
		String[] stringsSigSubTypes = new String[23];
		stringsSigSubTypes[0] = "END";
		stringsSigSubTypes[1] = SigSubTypes.FEATURES.toString();
		stringsSigSubTypes[2] = SigSubTypes.ISSUER.toString();
		stringsSigSubTypes[3] = SigSubTypes.KEY_EXPIRATION_TIME.toString();
		stringsSigSubTypes[4] = SigSubTypes.KEY_FLAGS.toString();
		stringsSigSubTypes[5] = SigSubTypes.KEY_SERVER_PREFERENCES.toString();
		stringsSigSubTypes[6] = SigSubTypes.NOTATION_DATA.toString();
		stringsSigSubTypes[7] = SigSubTypes.POLICY_URI.toString();
		stringsSigSubTypes[8] = SigSubTypes.PREFERRED_COMPRESSION_ALGORITHMS.toString();
		stringsSigSubTypes[9] = SigSubTypes.PREFERRED_HASH_ALGORITHMS.toString();
		stringsSigSubTypes[10] = SigSubTypes.PREFERRED_KEY_SERVER.toString();
		stringsSigSubTypes[11] = SigSubTypes.PREFERRED_SYMMETRIC_ALGORITHMS.toString();
		stringsSigSubTypes[12] = SigSubTypes.PRIMARY_USER_ID.toString();
		stringsSigSubTypes[13] = SigSubTypes.REASON_FOR_REVOCATION.toString();
		stringsSigSubTypes[14] = SigSubTypes.REGULAR_EXPRESSION.toString();
		stringsSigSubTypes[15] = SigSubTypes.REVOCABLE.toString();
		stringsSigSubTypes[16] = SigSubTypes.REVOCATION_KEY.toString();
		stringsSigSubTypes[17] = SigSubTypes.SIGNATURE_CREATION_TIME.toString();
		stringsSigSubTypes[18] = SigSubTypes.SIGNATURE_EXPIRATION_TIME.toString();
		stringsSigSubTypes[19] = SigSubTypes.SIGNATURE_TARGET.toString();
		stringsSigSubTypes[20] = SigSubTypes.SIGNERS_USER_ID.toString();
		stringsSigSubTypes[21] = SigSubTypes.TRUST_SIGNATURE.toString();
		stringsSigSubTypes[22] = SigSubTypes.EXPORTABLE_CERTIFICATION.toString(); 

		this.stringsSigSubTypes = stringsSigSubTypes;
		
		
	}
	public void reconstructStrings(){
		String[] strings = null;
		if (model.isPubKeyAdded() == false){
			strings = new String[1];
			strings[0] =KindOfEntry.PubKey.toString();
		}
		else if(model.isFirstUserIDAdded() && model.isFirstUserAttrAdded() == false && model.isFirstSubKeyAdded() == false && model.isFirstSubKeyRevAdded() == false ){
			strings = new String[3];
			strings[0] =KindOfEntry.UserID.toString();
			strings[1] =KindOfEntry.UserAttr.toString();
			strings[2] =KindOfEntry.SubKey.toString();
			System.out.println("asdasdasd "+model.isFirstSubKeyAdded() );
		}
		else if(model.isFirstUserAttrAdded() == true && model.isFirstSubKeyAdded() == false && model.isFirstSubKeyRevAdded() == false){ 
			strings = new String[2];
			strings[0] =KindOfEntry.UserAttr.toString();
			strings[1] =KindOfEntry.SubKey.toString();
		}
		else if(model.isFirstSubKeyAdded() && model.isFirstSubKeyRevAdded() == false){
			strings = new String[2];
			strings[0] =KindOfEntry.SubKey.toString();
			strings[1] =KindOfEntry.SigRevSubKey.toString();
		}
		else if(model.isFirstSubKeyRevAdded()){
			strings = new String[1];
			strings[0] =KindOfEntry.SigRevSubKey.toString();
		}
		else{
			//pubkey is added but no other packet yet
			strings = new String[1];
			strings[0] =KindOfEntry.UserID.toString();
			
		}
		this.strings = strings;
		
		
	}
	
	@Override
	public void actionPerformed(ActionEvent arg0) {
		
		if(model.isRemovedOptionUsed()){
			//do some clean up
			
			model.setFirstSubKeyAdded(false);
			model.setFirstUserAttrAdded(false);
			model.setFirstUserIDAdded(false);
			model.setSubKeyRevAdded(false);
			
			Entry entry;
			for(int i=0; i< model.getNumOfEntries(); i++){
				entry = model.getEntry(i);
				if(entry.getType() == KindOfEntry.SigRevPubKey){
					model.setSubKeyRevAdded(true);
				}
				if(entry.getType() == KindOfEntry.UserID){
					model.setFirstUserIDAdded(true);
				}
				if(entry.getType() == KindOfEntry.UserAttr){
					model.setFirstUserAttrAdded(true);
				}
				if(entry.getType() == KindOfEntry.SubKey){
					model.setFirstSubKeyAdded(true);
				}
				
			}
			
			
			/*
			 * if the last package available is a 
			 */
			String[] strings = {};
			switch(model.getEntry(model.getNumOfLastEntry()).getType()){
			case SigRevPubKey:
			case SigRevSubKey:
			case SigUserAttr:
			case SigUserID:
					//strings have to be empty	
				this.strings = strings;
				break;
			case Text: // can be: end of sig, beginning of sig
				if(model.getEntry(model.getNumOfLastEntry()).getText() == endSignature){
					reconstructStrings();
				}
				else if (model.getEntry(model.getNumOfLastEntry()).getText() == beginHashedSubPackets){
					reconstructstringsSigSubTypes();
					this.strings = this.stringsSigSubTypes;
				}
				else if (model.getEntry(model.getNumOfLastEntry()).getText() == beginUnhashedSubPackets){
					reconstructstringsSigSubTypes();
					this.strings = this.stringsSigSubTypes;
				}
				else{
					System.err.println("I forgot to think about: "+ model.getEntry(model.getNumOfLastEntry()).getText() +" text entries at the cleanup function");
				}
				break;
			case UserID:
				//leave emtpry, so that another user id including
				this.strings = strings;
				break;
			case PubKey:
				reconstructStrings();
				break;
			default:
				// I do not care
				break;
			}
			
			

			view.getGenEntry().setComboBoxContent(this.strings);
			model.setRemovedOptionUsed(false);
			return;
		}
					
		
		//create first entry - pubkey
		if (model.getNumOfEntries() == 0 ){
			if (model.isPubKeyAdded()  == false){
				model.addPubKey();
				view.updateView(model);
			}
		}
		else if(model.getNumOfEntries() == 1){//first packet has to be treated differently
			//subkey cant be at first position
			
			JComboBox combo = (JComboBox)arg0.getSource();
			
			String test = combo.getSelectedItem().toString();
			
			if (test == userID){
				logicUserID(combo);
			}
			else if (test == userAttr){
				logicUserAttr(combo);
			}
		}
		//everything after the pubkey
		else{
			KindOfEntry lastEntry = model.getEntry(model.getNumOfLastEntry()).getType();
			JComboBox combo = (JComboBox)arg0.getSource();
			
			if(combo.getSelectedItem().toString() == "Public Key"){
				return;
			}
			switch (lastEntry){
			case PubKey:
				break;
			case UserAttr:
				logicUserAttr(combo);
				break;
			case UserID:
				logicUserID(combo);
				break;
			case hashedSubPacket:
				logicHashedSubPacket(combo);
				break;
			case UnhashedSubPacket:
				logicUnhashedSubPacket(combo);
				break;
			case Text:
				logicText(combo);
				break;
			case SubKey:
				logicSubKey(combo);
			case SigRevSubKey:
				logicSubKey(combo);
			default:
				System.err.println("logic first switch following entry does not exist: "+ model.getEntry(model.getNumOfLastEntry()).getType());
			}
		
		}
		
		
		if (hasSigBegun == false){
			reconstructStrings();
			view.getGenEntry().setComboBoxContent(strings);
		}
	}
	/*
	 * beginHashedSubPackets = "Hashed SubPackets";
	private String beginUnhashedSubPackets = "UnHashed SubPackets";
	private String endSignature = " ";
	 */
	
	private void logicText(JComboBox combo) {
		// before:endSignature, end of hashed, end of unhashed
		
		//last entry is the beginning of hashed subpackets
		if (model.getEntry(model.getNumOfLastEntry()).getText() == beginHashedSubPackets){
			
			//if end is selected begin with unhashed subpackets
			if(combo.getSelectedItem().toString() == "END"){// check if it is last item (end)

				model.addTextEntry(beginUnhashedSubPackets,3);
				//restore Strings and combobox for unhashed subpackets
				reconstructstringsSigSubTypes();
				view.getGenEntry().setComboBoxContent(stringsSigSubTypes);
			}//next will be unhashed subpackets
			
			else{// end is not selected, other hashed subpackets will follow
				model.addHashedSigSubEntry(SigSubTypes.fromString(combo.getSelectedItem().toString()),  ctrLastSig);//sigsubtype selected in combo box
				//remove used subpacket from list && update combobox
				stringsSigSubTypes = removeStrFromArr(stringsSigSubTypes,combo.getSelectedItem().toString());
				view.getGenEntry().setComboBoxContent(stringsSigSubTypes);
			}//next will be unhashed subpackets in case unhashed subpackets
		}
		
		//last entry is the beginning of unhashed subpackets
		else if (model.getEntry(model.getNumOfLastEntry()).getText() == beginUnhashedSubPackets){

			//if end is selected begin with new main packet, such as userid, user attribute, subkey
			if(combo.getSelectedItem().toString() == "END"){
				model.addTextEntry(endSignature, 1);
				reconstructstringsSigSubTypes();
				this.hasSigBegun = false;
				view.getGenEntry().setComboBoxContent(strings);
			}//next will be case text if end signature
			else{//other unhashed subpackets will follow
				model.addUnhashedSigSubEntry(SigSubTypes.fromString(combo.getSelectedItem().toString()),  ctrLastSig);//sigsubtype selected in combo box
				//remove used subpacket from list && update combobox
				stringsSigSubTypes = removeStrFromArr(stringsSigSubTypes,combo.getSelectedItem().toString());
				view.getGenEntry().setComboBoxContent(stringsSigSubTypes);
			}
		}
		
		//last entry is the end of a signature 
		else if(model.getEntry(model.getNumOfLastEntry()).getText() == endSignature){
			String test = combo.getSelectedItem().toString();
			if (test == userID){
				logicUserID(combo);
			}
			else if (test == userAttr){
				logicUserAttr(combo);
			}
			else if (test == subKey){
				logicSubKey(combo);
			}
			else if(test == KindOfEntry.SigRevSubKey.toString()){
				logicSubKey(combo);
			}
			else{
				System.err.println("logic in adding Packets: case Text, if last = signature, wring element in combobox: "+combo.getSelectedItem().toString());
			}
		}
		else{
			System.err.println("to be implmeneted: "+model.getEntry(model.getNumOfLastEntry()).getText());
		}
		view.updateView(model);
	}

	private void logicSubKey(JComboBox combo) {
		//before: userid sig, user attr sig
		//after: subkey, subkeyrevokation
			if (combo.getSelectedItem().toString() == KindOfEntry.SigRevSubKey.toString()){
				model.addSignatureEntry(model.getLastNotSignaturePacket());
				ctrLastSig = model.getNumOfLastEntry();
				this.hasSigBegun = true;
				model.addTextEntry(beginHashedSubPackets, 3);
				view.getGenEntry().setComboBoxContent(stringsSigSubTypes);
			}
			else if (combo.getSelectedItem().toString() == KindOfEntry.SubKey.toString()){

				model.addSubKey();
			}
					
		
		
		
		view.updateView(model);
	}

	private void logicUnhashedSubPacket(JComboBox combo) {
		//before: another unhashed, beginUnhashedSubPackets
		
		//last entry is another unhashed subpacket
		if (model.getEntry(model.getNumOfLastEntry()).getType() == KindOfEntry.UnhashedSubPacket){
					
			//if end is selected begin with unhashed subpackets
			if(combo.getSelectedItem().toString() == "END"){
					
				model.addTextEntry(endSignature,3);
				
				//restore Strings and combobox for new start
				reconstructstringsSigSubTypes();
				this.hasSigBegun = false;
				view.getGenEntry().setComboBoxContent(strings);			
				//next will be case text if unhashed == true
			}
			else{	
				model.addHashedSigSubEntry(SigSubTypes.fromString(combo.getSelectedItem().toString()),  ctrLastSig);//sigsubtype selected in combo box
				//remove used subpacket from list && update combobox
				stringsSigSubTypes = removeStrFromArr(stringsSigSubTypes,combo.getSelectedItem().toString());
				view.getGenEntry().setComboBoxContent(stringsSigSubTypes);
			}
		}
		
		view.updateView(model);
	}

	private void logicHashedSubPacket(JComboBox combo) {
		//before: beginHashedSubPackets, another hashed
		
		//last entry is another hashed subpacket
		if (model.getEntry(model.getNumOfLastEntry()).getType() == KindOfEntry.hashedSubPacket){
			
			//if end is selected begin with unhashed subpackets
			if(combo.getSelectedItem().toString() == "END"){
				
				model.addTextEntry(beginUnhashedSubPackets,3);
				
				//restore Strings and combobox for unhashed subpackets
				reconstructstringsSigSubTypes();
				view.getGenEntry().setComboBoxContent(stringsSigSubTypes);			
				//next will be case text if unhashed == true
			}
			else{// not end but normol other subpackets
			
				model.addHashedSigSubEntry(SigSubTypes.fromString(combo.getSelectedItem().toString()),  ctrLastSig);//sigsubtype selected in combo box
				//remove used subpacket from list && update combobox
				stringsSigSubTypes = removeStrFromArr(stringsSigSubTypes,combo.getSelectedItem().toString());
				view.getGenEntry().setComboBoxContent(stringsSigSubTypes);
			}
		}
		
		view.updateView(model);
	}

	private void logicUserAttr(JComboBox combo) {
		//before:pubkey, endSignature
		model.addUserAttrEntry();
		model.addSignatureEntry(model.getLastNotSignaturePacket());
		ctrLastSig = model.getNumOfLastEntry();
		this.hasSigBegun = true;
		model.addTextEntry(beginHashedSubPackets, 3);
		view.getGenEntry().setComboBoxContent(stringsSigSubTypes);
				
		
		view.updateView(model);
	}

	private void logicUserID(JComboBox combo) {
		//before:pubkey,endSignature
		model.addUserIdEntry();
		model.addSignatureEntry(model.getLastNotSignaturePacket());
		ctrLastSig = model.getNumOfLastEntry();
		this.hasSigBegun = true;
		model.addTextEntry(beginHashedSubPackets, 3);
		view.getGenEntry().setComboBoxContent(stringsSigSubTypes);
				
		view.updateView(model);
	}

	/*
	 * removes an entry from an String arr
	 * returns null on failure
	 */
	public String[] removeStrFromArr(String[] arr, String str){
		int pos = -1;
		for(int i=0; i<arr.length; i++){
			if (arr[i] == str){
				pos = i;
				break;
			}
		}
		if (pos == -1){
			return null;
		}
		String[] out = new String[arr.length-1];
		System.arraycopy(arr, 0, out, 0, pos);
		System.arraycopy(arr, pos+1, out, pos, arr.length-pos-1);
		
		return out;
	}
	
}
