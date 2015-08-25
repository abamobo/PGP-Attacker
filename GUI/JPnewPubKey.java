import java.awt.Color;
import java.awt.Container;
import java.awt.Graphics;
import java.awt.LayoutManager;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import src.MPI;
import src.PubKeyAlgos;


public class JPnewPubKey extends JPanel{
	
	private byte[] time = null;
	private int version = 4;
	private String[] versions = {"4","3"};
	private String[] pubKeyAlgos = {PubKeyAlgos.RSA_ENC.toString(),PubKeyAlgos.RSA_ENC_OR_SIGN.toString()};
	private PubKeyAlgos pubKeyAlgo = null;
	private MPI  mpis[] = null;
	
	
	
	private JLabel jlTtime = new JLabel("creation time");
	private JTextField jtfTime = new JTextField("305419879");//in hex 0x12345678
	
	private JLabel jlVersion = new JLabel("version");
	private JComboBox jcVersion = new JComboBox(this.versions);
	
	private JLabel jlPubKeyAlgo = new JLabel("PubKey Algo");
	private JComboBox jcPubKeyAlgo = new JComboBox(this.versions);
	
	private JButton jbConfirm = new JButton("confirm");
	
	JPnewPubKey(Container contentPane){
		setBorder(BorderFactory.createLineBorder(Color.black));
		/*
		 * layout:
		 * multiple x_axis boylayouts, combined in a big y_axis boxlayout
		 */
		this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS)); 
		JPanel tmp = new JPanel();
		LayoutManager tmpLayoutManager = new BoxLayout(tmp, BoxLayout.X_AXIS);
		
	
		tmp.setLayout(tmpLayoutManager);
		tmp.add(jlTtime);
		tmp.add(jtfTime);
		
		this.add(tmp);
		
		tmp = new JPanel();
		tmpLayoutManager = new BoxLayout(tmp, BoxLayout.X_AXIS);
		tmp.setLayout(tmpLayoutManager);
		tmp.add(jlVersion);
		tmp.add(jcVersion);
		
		
		
		
		
		
		
		
		
	}
	
	protected void paintComponent(Graphics g){
		super.paintComponent(g);
	}
	
	
	
}
