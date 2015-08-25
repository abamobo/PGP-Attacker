package src;
import java.util.ArrayList;
/*
 * convention operations on the Body begin with a little b
 */
public abstract class Packet {
	
	protected Header head;
	
	protected ArrayList<Byte> whole = new ArrayList<Byte>();
	protected ArrayList<Byte> body = new ArrayList<Byte>();
	Packet(){
	}
	
	/*
	 * returns the header object if it is not zero
	 * return -1 on failure
	 */
	public int getHeaderLength(){
		if (head != null){
			return this.head.getLength();
		}
		else{
			System.err.println("Header is not instantiazed yet, dude change your constructor");
			return -1;
		}
	}
	/*
	 * returns the header object if it is not zero
	 */
	public Header getHeader(){
		if (head != null){
			return this.head;
		}
		else{
			System.err.println("Header is not instantiazed yet, dude change your constructor");
			return null;
		}
	}
	
	
	/*
	 * return the long body Length
	 * return -1, if header is not set yet, however schould never happen, since the header has to be instantiated in every constructor
	 */
	public long getBodyLen(){
		if (head != null){
			return head.getBodyLen();
		}
		else{
			System.err.println("Header is not instantiazed yet, dude change your constructor");
			return -1;
		}
	}
	
	/*
	 * returns the whole size of the Packet
	 */
	public long getWholePacketSize(){
		return this.whole.size();
	}
	
	/*
	 * returns the whole Packet as an byte array
	 */
	public byte[] getWholePacket(){
		byte[] data = new byte[whole.size()];
		
		for (int i=0; i<data.length; i++){
			data[i] = whole.get(i);
		}
		
		return data;
	}
	/*
	 * returns the whole Packet as an byte array
	 */
	public byte[] getBody(){
		byte[] data = new byte[body.size()];
		
		for (int i=0; i<data.length; i++){
			data[i] = body.get(i);
		}
		
		return data;
	}
}