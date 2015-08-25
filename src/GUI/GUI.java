package GUI;


import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import src.HashAlgorithms;
import src.SigSubTypes;
import src.SignatureSubPacket;
/*
 * controller
 */
/*
 * 
 * the class Model holds the metadata, to construct the packets themselves
 * 
 */
public class GUI extends JFrame{
	
	private static final long serialVersionUID = -8523799217956087512L;
	
	
	
	public GUI(){
		initJFrame();
		initComponents();
		
	}
	
	private void initJFrame(){
		this.setTitle("PGP-Attacker");
		setSize(600,700);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		this.setBounds(2080, 0, 780, 700);
		
		this.setResizable(false);
	}
	
	private void initComponents(){
		Container pane = this.getContentPane();
		
		
		
		Model model = Model.getInstance();//model
		JPView jpView = new JPView(pane,model);//);//view
		ControlPanel jpControl = new ControlPanel(pane,jpView, model);; // controller
		JPHead jpHead = new JPHead(pane, jpView, model);; // another controller
				
		//make View scrollable
		JScrollPane jspScroll = new JScrollPane(jpView);
		
		
		pane.add(jspScroll,BorderLayout.CENTER);
		pane.add(jpControl,BorderLayout.LINE_START);
		pane.add(jpHead,BorderLayout.PAGE_START);
		
		
		setVisible(true);
	}
}


