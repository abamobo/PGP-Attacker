import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JPanel;

import src.PacketBuilder;

/*
 * kind of MVC
 */
public class ControlPanel extends JPanel{
	private JButton JBaddPubKey = new JButton("add new PubKey");
	private JButton JBaddUserID = new JButton("add new User ID");
	private JButton JBaddUserAttribute = new JButton("add new User Attribute");
	private JButton JBaddSubKey = new JButton("add new SubKey");
	
	
	private JPnewPubKey jpNewPubKey;
	
	
	private String currentWorkDir = System.getProperty("user.dir");
	private final Path outPath = Paths.get(currentWorkDir, "PubKey.gpg");
	
	private Container contentPane; //  MAIN JFRAME 
	
	private final PacketBuilder packet = new PacketBuilder(outPath,"asd (asd) <asd@asd.com>"); // model
	
	private final ViewPanel vp = new ViewPanel(); // view
	
	ControlPanel(Container contentPane){
		this.contentPane = contentPane;
		System.out.println(outPath.toString());
		this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		this.jpNewPubKey =  new JPnewPubKey(this.contentPane);
		
		
		JBaddPubKey.addActionListener(new ActionListener(){

			@Override
			public void actionPerformed(ActionEvent e) {
				packet.addPubKeyPacket();
				updateView();
				System.out.println("added new public key");
				vp.repaint();
				setCenternewPubKey();
				
			}
			
		});
		
		this.add(JBaddPubKey);
		this.add(JBaddUserID);
		this.add(JBaddUserAttribute);
		this.add(JBaddSubKey);
		
		
		contentPane.add(this,BorderLayout.LINE_START);
		contentPane.add(vp,BorderLayout.LINE_END);
		
	}
	private void setCenternewPubKey(){
		contentPane.add(jpNewPubKey,BorderLayout.CENTER);
	}
	
	private void updateView(){
		vp.updateState(outPath);
	}
	
	public ViewPanel getViewPanel(){
		return this.vp;
	}
}

