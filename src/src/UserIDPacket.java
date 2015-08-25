package src;
//https://tools.ietf.org/html/rfc4880#section-5.11
/*
 * content is completly arbitrary
 */
public class UserIDPacket extends Packet{
	
	
	private byte[] data;
	
	public UserIDPacket(String payload){
		byte[] payl = Util.payload2Barr(payload);
		head = new Header(PacketTags.USER_ID,payl.length);
		
		data = new byte[head.getLength()+payl.length];
		System.arraycopy(head.getWholeHeader(), 0, data, 0, head.getLength());
		System.arraycopy(payl, 0, data, head.getLength(), payl.length);
		
	}
	public UserIDPacket(byte[] payload){
		head = new Header(PacketTags.USER_ID,payload.length);
		
		data = new byte[head.getLength()+payload.length];
		System.arraycopy(head.getWholeHeader(), 0, data, 0, head.getLength());
		System.arraycopy(payload, 0, data, head.getLength(), payload.length);
		
	}
	
	public byte[] getWholePacket(){
		return data;
	}
	public int getWholeLength(){
		return data.length;
	}
	
	public int getHeaderLength(){
		return head.getLength();
	}
	public int getLength(){
		return data.length;
	}
	
}
