package src;
import java.util.Arrays;

//https://tools.ietf.org/html/rfc4880#section-3.2
/*
 * NOTE: maximum size is 8224 bytes { (256*256+256)/8 }
 * the size of an MPI is a 2 octet scalar in bits,
 * 0xFFFF = 65535
 */
public class MPI {

	Scalar lenScalar;//length
	byte[] data; //data
	byte[] whole; // scalar + data
	
	final static int MAX_SIZE = 0xFFFF + 1 ;//0xFFFF +1 = 2^16 

	/*
	 * generate an MPI from an payload
	 */
	MPI(String str){
		this(Util.payload2Barr(str));
	}
	
	/*
	 * generate an MPI from an byte arr (arr is here only the data without size)
	 */
	public MPI(byte[] dat){
		setKeyData(dat);
	}
	
	/*
	 * read an existing MPI in
	 */
	public void setKeyData(byte[] arr, int offset){
		lenScalar = new Scalar(arr[offset],arr[offset+1]);
		int dataLen = (int) lenScalar.getLength();
		
		this.data = new byte[dataLen];
		this.whole = new byte[dataLen+2];
		
		if(offset+2+dataLen > arr.length){
			System.err.println("wrong offset specified, the read in size does not match the available bytes");
			System.exit(0);
		}
		
		System.arraycopy(arr, offset+2, this.data, 0, dataLen);//copy data from arr to data
		System.arraycopy(this.data, 0, whole, 2, dataLen ); // copy data from data to whole
		
		whole[0] = arr[offset];
		whole[1] = arr[offset+1];
	}
	
	/*
	 * replaces the old data with new data
	 */
	public void setKeyData(byte[] dat){
		int dataLen = dat.length;
		//System.out.println("__________________________________\nMPI setKeyData");
		//System.out.println("datalen [bytes] "+dataLen);
		lenScalar = new Scalar(dataLen*8,2);// create a 2 octet scalar for the size in Bits not in bytes
		
		this.data = dat;
		whole = new byte[dataLen+2];
		
		System.arraycopy(this.data, 0, whole, 2, dataLen); // copy byte data into whole byte[]
		
		/*//System.out.println("dataLen(bits) "+dataLen);
		//System.out.println("dataLen(bytes) "+dataLen/8);
		dat = lenScalar.getSizeInBitsAsByteArr();
		//System.out.println(" "+ Arrays.toString(dat));
		////System.out.println("1 "+dat[0]+","+dat[1]);
		*/
		dat = lenScalar.getSizeInBitsAsByteArr();
		whole[0] =  (dat[0]);
		whole[1] =  (dat[1]);
		////System.out.println("whole MPI  "+ Arrays.toString(whole));
		//System.out.println("datalen "+dataLen);
		/*whole[0] = lenScalar.getSizeInBitsAsByteArr()[0];
		whole[1] = lenScalar.getSizeInBitsAsByteArr()[1];*/
		//System.out.println("__________________________________");
	}
	
	public byte[] getWholeMPI(){
		return whole;
	}
	public int getDataSizeBits(){
		return (int) lenScalar.getLength();
	}
	public int getDataSizeBytes(){
		return (int) lenScalar.getLength()/8;
	}
	public int getSizeBytes(){
		if (whole == null){
			System.err.println("should not happen");
		}
		return whole.length;
	}
	public byte[] getKeyData(){
		return data;
	}
	
}
