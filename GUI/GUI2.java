import java.awt.BorderLayout;
import java.awt.Container;
import javax.swing.JFrame;

/*
 * this is merely starts the controller
 */
public class GUI2 extends JFrame{
	
	private static final long serialVersionUID = -8523799217956087512L;
	private ViewPanel vp = null;
	private ControlPanel cp = new ControlPanel(this.getContentPane());
	
	GUI2(){
		init();
	}
	
	private void init(){
		this.setTitle("PGP-Attacker");
		setSize(600,900);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		setVisible(true);
		
	}
}


