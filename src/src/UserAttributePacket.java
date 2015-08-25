package src;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;

/*
 * https://tools.ietf.org/html/rfc4880#section-5.12
 */
public class UserAttributePacket extends Packet{
	
	
	//byte[] whole = new byte[(int) FileUtil.MAX_ARR_SIZE];
	
	Path path = FileSystems.getDefault().getPath("src", "iptc_attacker_img.jpg");
	boolean iscustomPayload = false;
	
	UserAttributePacket(){
		this("",true);
	}
	
	/*public long calcSubPacketBodyLen(){
		long size = 0;
		
		size += 17;// static header
		if (!iscustomPayload){
			size += FileUtil.getFileLength(this.path); // length in bytes of image
		}else{//custom Payload
			size += this.payl.length; // length in bytes of string payload
		}
		return size;
	}*/
	/*
	 * if standardPayload is true String payload will be ignored and the contents of the image file will be used
	 */
	public UserAttributePacket(String payload, boolean customPayload){
		this(Util.payload2Barr(payload), customPayload);
	}
	public UserAttributePacket(byte[] payload, boolean customPayload){
		this.iscustomPayload =customPayload; 
		//1. create subpacket
		//A: append static 17 byte IMAGE header, since it is the only one possible, this is only a header for the image not the subpacket itself
		whole.add((byte) 0x01);//1
		whole.add((byte) 0x10);
		whole.add((byte) 0x00);
		whole.add((byte) 0x01);
		whole.add((byte) 0x01);
		
		whole.add((byte) 0x00);//5
		whole.add((byte) 0x00);
		whole.add((byte) 0x00);
		whole.add((byte) 0x00);
		whole.add((byte) 0x00);
		
		whole.add((byte) 0x00);//10
		whole.add((byte) 0x00);
		whole.add((byte) 0x00);
		whole.add((byte) 0x00);
		whole.add((byte) 0x00);
		
		whole.add((byte) 0x00);//16
		whole.add((byte) 0x00);//17
		
		//B: insert data
		if (!iscustomPayload){
			try { 
				byte[] fileData;
				fileData = Files.readAllBytes(path);
				for(int i=0; i< fileData.length; i++){
					whole.add(fileData[i]);
				}
			} catch (IOException e) {
				System.err.println("ioexception reading image file for userattribute packet");
				e.printStackTrace();
			}
		}
		else{//customPayload
			
			for (int i=0; i<payload.length; i++){
				whole.add(payload[i]);
			}
		}
				 
		//C: prepend subpacket header
		int bodyLen = whole.size();
		if (bodyLen > 0 && bodyLen <= 191){
			whole.add(0,(byte) bodyLen);
		}
		else if(bodyLen >= 192 && bodyLen <= 8383){
			byte tmp = ((byte) (((bodyLen-192)>> 8)+192));
			whole.add(0,tmp);
			whole.add(1,(byte) ( bodyLen - 192 - ((tmp-192)<<8)));
		}
		else if (bodyLen >= 8384 && bodyLen <= 0xFFFFFFFFL){
			whole.add(0,(byte) 255);
			whole.add(1,(byte) (bodyLen >> 24)); 
			whole.add(2,(byte) (bodyLen >> 16)); 
			whole.add(3,(byte) (bodyLen >> 8)); 
			whole.add(4,(byte) (bodyLen >> 0));
		}

		
		//2. prepend header to userAttr packet
		head = new Header(PacketTags.USER_ATTRB,whole.size());
		for (int i=0; i<head.getWholeHeader().length; i++){
			whole.add(i, (byte) head.getWholeHeader()[i]);
		}

	}
	

	public int getSize(){
		return head.getBodyLen()+head.getLength();
	}

	public int getHeaderLength() {
		return head.getOffsetBody();
	}
}
