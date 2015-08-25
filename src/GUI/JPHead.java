package GUI;

import java.awt.Color;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.SwingConstants;

import src.HashAlgorithms;
import src.SigSubTypes;
import src.SignatureSubPacket;


/*
 * this jpanel fills the page_start part of the borderlayout
 */
public class JPHead extends JPanel{
	private JButton jbdefaultSettings = new JButton("default Settings");
	private JButton jbCheckAll = new JButton("check all");
	private JButton jbUnCheckAll = new JButton("Uncheck all");
	
	private JButton jbGenerate = new JButton("generate Packet");
	
	
	JPHead(Container contentPane, JPView jpView, Model model){
		this.setPreferredSize(new Dimension(contentPane.getWidth(),50));
		this.setLayout(new BoxLayout(this,BoxLayout.X_AXIS));
		this.setBorder(BorderFactory.createLineBorder(Color.black));
		
		jbdefaultSettings.addActionListener(new DefaultSettingsActionListener(model,jpView));
		jbCheckAll.addActionListener(new CheckAllActionListener(model,jpView));
		jbUnCheckAll.addActionListener(new UNCheckAllActionListener(model,jpView));
		jbGenerate.addActionListener(new GenerateActionListener(model,jpView));
		this.add(jbdefaultSettings);
		this.add(Box.createRigidArea(new Dimension(30,0)));
		this.add(jbCheckAll);
		this.add(jbUnCheckAll);
		this.add(Box.createRigidArea(new Dimension(55,0)));
		this.add(jbGenerate);
	}
}

class CheckAllActionListener implements ActionListener{
	private Model model = null;
	private JPView jpView = null;
	CheckAllActionListener(Model model, JPView jpView){
		this.model = model;
		this.jpView = jpView;
	}
	
	@Override
	public void actionPerformed(ActionEvent e) {
		/*
		 * 1. edit model
		 */
		Entry entry = null;
		for (int i=0; i< model.getNumOfEntries(); i++){
			entry = model.getEntry(i);
			entry.check();
		}
		/*
		 * 2. edit view
		 */
		
		jpView.updateView(model);
		
	}
	
}
class UNCheckAllActionListener implements ActionListener{

	private Model model = null;
	private JPView jpView = null;
	
	UNCheckAllActionListener(Model model, JPView jpView){
		this.model = model;
		this.jpView = jpView;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		Entry entry = null;
		for (int i=0; i< model.getNumOfEntries(); i++){
			entry = model.getEntry(i);
			entry.unCheck();
		}
		
	}
	
}
class DefaultSettingsActionListener implements ActionListener{
	
	private Model model;
	private JPView view;
	private SignaturePreference sigPref;
	
	DefaultSettingsActionListener(Model model, JPView jpView){
		this.model = model;
		this.view = jpView;
		this.sigPref = new SignaturePreference();
	}
	public void createSigPref(){
		
		
		
		ArrayList<SubPacketMetaData> hashedSubPackets = new ArrayList<SubPacketMetaData>();
		ArrayList<SubPacketMetaData> UNhashedSubPackets = new ArrayList<SubPacketMetaData>();
		
		boolean insertPayload = true;
		boolean dontInsertPayload = false;
		boolean isUnhashedSubPacket = true;
		boolean isHashedSubPacket = false;
		
		//subpackets where a payload can be injected
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.PREFERRED_KEY_SERVER,isHashedSubPacket, insertPayload));
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.REGULAR_EXPRESSION,isHashedSubPacket, insertPayload));
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.SIGNERS_USER_ID,isHashedSubPacket, insertPayload));
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.NOTATION_DATA,isHashedSubPacket, insertPayload));
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.POLICY_URI,isHashedSubPacket, insertPayload));
		
		//these subpackets are generated by gpg at default
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.SIGNATURE_CREATION_TIME,isHashedSubPacket, dontInsertPayload));
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.KEY_FLAGS,isHashedSubPacket, dontInsertPayload));
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.KEY_EXPIRATION_TIME,isHashedSubPacket, dontInsertPayload));
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.PREFERRED_COMPRESSION_ALGORITHMS,isHashedSubPacket, dontInsertPayload));
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.PREFERRED_HASH_ALGORITHMS,isHashedSubPacket, dontInsertPayload));
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.PREFERRED_SYMMETRIC_ALGORITHMS,isHashedSubPacket, dontInsertPayload));
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.FEATURES,isHashedSubPacket, dontInsertPayload));
		hashedSubPackets.add(new SubPacketMetaData (SigSubTypes.KEY_SERVER_PREFERENCES,isHashedSubPacket, dontInsertPayload));
		
		
		UNhashedSubPackets.add(new SubPacketMetaData (SigSubTypes.ISSUER,isUnhashedSubPacket, dontInsertPayload));
		
		this.sigPref.setUNhashedSubPackets(UNhashedSubPackets);
		this.sigPref.setHashedSubPackets(hashedSubPackets);
	}
	
	@Override
	public void actionPerformed(ActionEvent e) {
		model.clear(this.view);
		createSigPref();
		model.addPubKey();
		model.addUserIdEntry();
		model.addSignatureEntry2(this.sigPref, model.getNumOfLastEntry());
		model.addUserAttrEntry();
		model.addSignatureEntry2(this.sigPref, model.getNumOfLastEntry());
		model.addTextEntry("",3);//end signature
		
		String[] strings = { KindOfEntry.UserAttr.toString(),  KindOfEntry.SubKey.toString()};
		view.getGenEntry().setComboBoxContent(strings);
		
		view.updateView(model);
	}
	
}


class GenerateActionListener implements ActionListener{

	private Model model = null;
	private JPView jpView = null;
	
	GenerateActionListener(Model model, JPView jpView){
		this.model = model;
		this.jpView = jpView;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		System.out.println("not implemented yet");
		new Trafo(model);
		model.checkAll();
		
	}
	
}

