package src;
/*
 * focus mainly on new header, old header is deprecated
 */
public class Header {
	
	private boolean isNewPacketFormat; 
	private int tag;
	private byte[] data;
	private int bodyLen;
	private int offsetBody;
	private int offsetHeader;
	private int offsetLength; // the offset where the length of the packet is  specified
	private int headerLen;
	/*
	 * get an unisgned int out of a signed byte
	 * 
	 */
	public static int UB(byte b){
		if (b < 0){
			return  (b & 0xFF);
		}else{
			return b ;
		}
	}
	public static int UBa(byte[] arr, int offset){
		return UB(arr[offset]);
	}
	
	/*
	 * use this constructor to read data from an existing header
	 */
	Header(byte[] data, int offset){
		this.data = data;
		this.offsetHeader = offset;
		
		//begin read packet tag
		/*
		 *       +---------------+
         	PTag |7 6 5 4 3 2 1 0|
                 +---------------+
         	Bit 7 -- Always one
         	Bit 6 -- New packet format if set
		 */

		if (Util.isBitSet(data[offsetHeader+0], 6)){
			this.isNewPacketFormat = true;
			/* Bits 5-0 -- packet tag */
			tag = Util.getSubSetOfBits(data[offsetHeader], 5,0); 
		}
		else{
			this.isNewPacketFormat = false;
			/* Bits 5-2 -- packet tag
         	 * Bits 1-0 -- length-type */
			tag = Util.getSubSetOfBits(data[offsetHeader], 5,2); 
			//lengthType = Util.getSubSetOfBits(UBa(data,offsetHeader], 1,0); 
		}	
		//end read packet tag
		
		//begin read offset body and bodyLen
		if (isNewPacketFormat){ // new packet format
			System.out.println("new header format");
			// test if one-octet length, to verify this the first octet has to be smaller than 192
			if(UBa(data,offsetHeader+1) < 192){
				System.out.println("one-octet length");
				offsetBody = 2;
				bodyLen = UBa(data,offsetHeader+1);
			}
			// test if length is 2 octet long
			else if (UBa(data,offsetHeader+1) >= 192 && UBa(data,offsetHeader+1) <=233){
				System.out.println("two-octet length");
				offsetBody = 3;
				bodyLen = (UBa(data,offsetHeader+1)-192)<<8 + UBa(data,offsetHeader+2) +192;
			}
			//test if length is 5 octets
			else if (UBa(data,offsetHeader+1) ==255){
				System.out.println("five-octet length");
				offsetBody = 6;
				bodyLen = UBa(data,offsetHeader+2)<<24 | UBa(data,offsetHeader+3)<< 16 |
						  UBa(data,offsetHeader+4)<< 8 | UBa(data,offsetHeader+5);
			}
			//test if partial body length
			else if(UBa(data,offsetHeader+1) >= 234 && UBa(data,offsetHeader+1) < 255){
				//https://tools.ietf.org/html/rfc4880#section-4.2.2.4
				//TODO finish
				offsetBody = 2;
				bodyLen = 1 << (UBa(data,offsetHeader+1)& 0x1F);
			}
			else{
				System.out.println("this should not happen");
			}
					
		}
		else{
			//old packet version
			int lengthType = Util.getSubSetOfBits((byte)UBa(data,offsetHeader), 1, 0);
			
			offsetLength = offsetHeader + 1;
			switch(lengthType){
			
			case 0:
				bodyLen = UBa(data,offsetLength);
				offsetBody = offsetHeader + 2;
				headerLen = 2;
				break;
			case 1:
				bodyLen = UBa(data,offsetLength)<<8 |  UBa(data,offsetLength+1);
				offsetBody = offsetHeader + 3;
				headerLen = 3;
				break;
			case 2:
				bodyLen = UBa(data,offsetLength)<<32 |  UBa(data,offsetLength+1)<<16 |UBa(data,offsetLength+2)<<8 |  UBa(data,offsetLength+3);
				offsetBody = offsetHeader + 5;
				headerLen = 5;
				break;
			case 3:
				bodyLen = -1; //undetermined length //TODO complete
				offsetBody = offsetHeader + 1;
				headerLen = 1;
				break;
			default:
				System.out.println("invalid length type. Exiting nau");
				System.exit(0);
			}
		}
		
		//end read offset body and bodyLen
	}
	
	/*
	 * use this constructor to create a new header
	 * this creates always a new header, yet TODO:old header
	 */
	Header (PacketTags tag, int bodyLen){
		this((int)tag.getNum(), bodyLen);
	}
	
	Header(int tag, int bodyLen){
		this.offsetHeader = 0;
		this.offsetLength = 1;
		this.bodyLen = bodyLen;
		
		//begin set length header fields
		if (bodyLen > 0 && bodyLen <= 191){
			//System.out.println("new header is 2 bytes long");
			this.offsetBody = 2;
			this.data = new byte[2];
			data[1] = (byte) bodyLen;//TODO what if size is bigger than 128(maximum byte size)
		}
		else if(bodyLen >= 192 && bodyLen <= 8383){
			this.offsetBody = 3;
			//System.out.println("new header is 3 bytes long");
			this.data = new byte[3];
			data[1] = (byte) (((bodyLen-192)>> 8)+192);
			data[2] = (byte) ( bodyLen - 192 - ((data[1]-192)<<8));
			/*System.out.println((byte) ((bodyLen-192)/256+192) );
			System.out.println("data[1] "+data[1]);
			System.out.println("data[2] "+data[2]);*/
		}
		else if (bodyLen >= 8384 && bodyLen <= 0xFFFFFFFFL){
			this.offsetBody = 6;
			//System.out.println("new header is 6 bytes long");
			this.data = new byte[6];
			data[1] = (byte) 255;
			data[2] = (byte) (bodyLen >> 24);
			data[3] = (byte) (bodyLen >> 16);
			data[4] = (byte) (bodyLen >> 8);
			data[5] = (byte) (bodyLen >> 0);
		}
		else{
			System.err.println("body len "+bodyLen+" is too long for new header");
		}
		this.headerLen = this.bodyLen - 1;
		//end set length header fields
		
		//begin set packet tag
		/*           +---------------+
		      	PTag |7 6 5 4 3 2 1 0|
		             +---------------+
		       	Bit 7 -- Always one
		       	Bit 6 -- New packet format if set
		 */
		//use always new packet format
		data[offsetHeader]  = (byte) 0x80; // bit 7
		data[offsetHeader] += (byte) 0x40; // bit 6
		data[offsetHeader] += tag;
		//end set packet tag
							
	}
	
	/*public  void setHeader(byte tag){
		byte dat = (byte) 0x80; // byte 7 is always set
		
		this.isNewPacketFormat = true; //use always new packet format
		dat += (byte) 0x40;//set 6. bit
		
		dat  += tag;
		
		this.data = dat;
	}*/
	public int getPacketLen(){
		return bodyLen+headerLen;
	}

	public int getBodyLen(){
		return bodyLen;
	}	
		
	public int getTag() {
		return tag;
	}
	
	public boolean getIsNewPacketFormat(){
		return isNewPacketFormat;
	}

	public int getOffsetHeader() {
		return offsetHeader;
	}	
	
	public int getOffsetBody(){
		return offsetBody;
	}

	public byte[] getWholeHeader(){
		//byte[] h = new byte[headerLen];
		return data;
	}
	public int getLength(){
		return data.length;
	}
}
