import java.awt.Color;
import java.awt.Graphics;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.ArrayList;

import javax.swing.BorderFactory;
import javax.swing.JPanel;


public class ViewPanel extends JPanel{
	
	private ArrayList<String> state = new ArrayList<String>();
	private boolean asd = false;
	ViewPanel(){
		setBorder(BorderFactory.createLineBorder(Color.black));
	}
	
	protected void paintComponent(Graphics g){
		super.paintComponent(g);
		for (int i=0; i<state.size(); i++){
			g.drawString(state.get(i),0,i*15);
		}			
	}
	
	/*
	 * add the results of gpg --list-packets to the state
	 */
	public void updateState(Path inPath){
		Process process;
		this.state = new ArrayList<String>();
		try {
			process = new ProcessBuilder("gpg","--list-packets",inPath.toString()).start();
			System.out.println(inPath.toString());
			InputStream is = process.getInputStream();
			InputStreamReader isr = new InputStreamReader(is);
			BufferedReader br = new BufferedReader(isr);
			String line;
			while ((line = br.readLine()) != null ) {
				this.state.add(line);
				System.out.println(line);
			}
		} catch (IOException e) {
			System.err.println("Error reading file "+inPath.toString()+" in");
			e.printStackTrace();
		}
	}
	

}