package GUI;

import java.nio.file.Path;
import java.nio.file.Paths;

import src.FileUtil;

/*
 * this class takes the info stored in the model class and then creates with this data all neccessary packets
 */
public class Trafo {
	
	private final Path path = Paths.get(System.getProperty("user.dir"), "PubKey.gpg"); // current work dir of the executable
	private FileUtil fu = new FileUtil(path);
	private Model model;
	/*
	 * use this constructor to generate all packets, listed in model
	 */
	public Trafo(Model model) {
		this.model = model;
		/*
		 * traverse through entries and write them sequentally to the file
		 */
		Entry entry = null;
		for (int i = 0; i<model.getNumOfEntries(); i++){
			entry = model.getEntry(i);
			
			switch (entry.getType()){
			case PubKey:
				writePubKey();
				break;
			case SigRevPubKey:
				
				break;
			case SigRevSubKey:
				
				break;
			case SigUserAttr:
				
				break;
			case SigUserID:
				
				break;
			case UserID:
				
				break;
			case UserAttr:
				
				break;
			default:
				//ignore rest
			}
		}
	}
	
	
	private void writePubKey(){
		
	}
	
	private void writeSubKey(){
		
	}

}
