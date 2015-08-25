package src;
import java.util.Arrays;

/*
 * https://tools.ietf.org/html/rfc4880#section-3.1
 */
public class Scalar {
	
	int size ; // possibble sizes 2,4,8 (keyid is an 8 octet scalar), 5(subpacket length)
	int[] data; // holds all data as an integer, because this way it is possible to use unsigned values instaead of signed bytes, which makes size calculations easier
	
	Scalar(long len, int size){
		this.size = size;
		switch (size){
		case 2:
			this.setLength2((int)len);
			break;
		case 4:
			this.setLength4((int)len);
			break;
		case 5:
			this.setLength5((int)len);
			break;
		case 8:
			this.setLength8(len);
			break;
		default:
			System.err.println("Scalars can only be of size 2,4,5,8");
		}
		
	}
	/*
	 * use this constructor 2 create a 2 octet scalar
	 */
	Scalar(byte val1, byte val2){
		this.size = 2;
		data = new int[this.size];
		data[0] = val1 & 0xFF; // signed byte to unsigned int
		data[1] = val2 & 0xFF;
	}
	
	/*
	 * use this constructor 2 create a 4 octet scalar
	 */
	Scalar(byte val1, byte val2, byte val3, byte val4){
		this.size = 4;
		data = new int[this.size];
		data[0] = val1 & 0xFF;
		data[1] = val2 & 0xFF;
		data[2] = val3 & 0xFF;
		data[3] = val4 & 0xFF;
	}
	
	/*
	 * use this constructor 2 create a 5 octet scalar
	 */
	Scalar(byte val1, byte val2, byte val3, byte val4, byte val5){
		this.size = 5;
		data = new int[this.size];
		data[0] = val1 & 0xFF;
		data[1] = val2 & 0xFF;
		data[2] = val3 & 0xFF;
		data[3] = val4 & 0xFF;
		data[4] = val4 & 0xFF;
	}
	
	/*
	 * use this constructor 2 create a 8 octet scalar
	 */
	Scalar(byte val1, byte val2, byte val3, byte val4, byte val5, byte val6, byte val7, byte val8){
		this.size = 8;
		data = new int[this.size];
		data[0] = val1 & 0xFF;
		data[1] = val2 & 0xFF;
		data[2] = val3 & 0xFF;
		data[3] = val4 & 0xFF;
		data[4] = val5 & 0xFF;
		data[5] = val6 & 0xFF;
		data[6] = val7 & 0xFF;
		data[7] = val8 & 0xFF;
	}
	/*
	 * method to read an existing scalar from an byte array
	 */
	public void readScalar(byte[] arr, int offset, int size){
		if (size != 2 && size != 4 && size != 8  && size != 5){
			System.err.println("invalid size for a scalar specified");
		}
		this.size = size;
		data = new int[size];
		for (int i=0; i<size;i++){
			data[i] = arr[offset] & 0xFF; // signed byte to unsigned int
		}
	}
	
	/*
	 * returns the length encoded by the values
	 */
	public long getLength(){
		long len = 0;
		/*
		 * size = 2
		 * data[0] << 8 + data[1]
		 * 
		 * size = 4
		 * data[0] << 24+ data[1] << 16 +data[2] <<8 +data[3]
		 * 
		 * size = size for i : 0 to size-1
		 * data[i] << 8*(size-1-i))
		 */
		
		for(int i=0;i<size;i++){
			len += (data[i] << 8*(size-1-i));  
		}
		
		return len;
	}
	/*
	 * use this method to create a 2 octet scalar from an integer length
	 */
	public void setLength2(int len){
		this.size = 2;
		data = new int[this.size];
		
		data[0] = len >> 8 % 0x100;
		data[1] = len      % 0x100;
	}
	
	/*
	 * use this method to create a 2 octet scalar from an integer length
	 */
	public void setLength4(int len){
		this.size = 4;
		data = new int[this.size];
		
		data[0]  = len >> 24 % 0x100; 
		data[1] =  len >> 16 % 0x100;
		data[2]  = len >>  8 % 0x100; 
		data[3] =  len       % 0x100;
	}
	
	/*
	 * use this method to create a 2 octet scalar from an integer length
	 */
	public void setLength5(int len){
		this.size = 5;
		data = new int[this.size];

		data[0] =  len >> 32 % 0x100;
		data[1]  = len >> 24 % 0x100; 
		data[2] =  len >> 16 % 0x100;
		data[3]  = len >>  8 % 0x100; 
		data[4] =  len       % 0x100;
	}	
	/*
	 * use this method to create a 2 octet scalar from an long length ( integer len holds only 4 byte, long holds 8 byte)
	 */
	public void setLength8(long len){
		this.size = 8;
		data = new int[this.size];
		/*
		 * info: % 0x100 sís done for better readability insode the int array, so no value execceds 256
		 */
		data[0]  = (int) ((len >> 56) % 0x100); 
		data[1] =  (int) ((len >> 48) % 0x100);
		data[2]  = (int) ((len >> 40) % 0x100); 
		data[3] =  (int) ((len >> 32) % 0x100);
		data[4]  = (int) ((len >> 24) % 0x100); 
		data[5] =  (int) ((len >> 16) % 0x100);
		data[6]  = (int) ((len >>  8) % 0x100); 
		data[7] =  (int) (len         % 0x100);
	}
	
	/*
	 * returns the data array as an byte array
	 */
	public byte[] getWholeScalar(){
		return intArr2ByteArr(data);
	}
	/*
	 * turns the int array data into an byte array
	 */
	private byte[] intArr2ByteArr(int[] iArr){
		byte[] bArr = new byte[iArr.length];
		for (int i=0; i<iArr.length;i++){
			bArr[i] = (byte) iArr[i];
		}
		return bArr;
	}
	/*
	 * return an byte array of length in bits (used for MPIs)
	 */
	public byte[] getSizeInBitsAsByteArr(){
		byte[] out = new byte[this.size];
		
		//System.out.println("scalar data int  "+Arrays.toString(data));
		for (int i =0;i<this.size;i++){
			out[i] = (byte)(data[i]);
		}
		//System.out.println("scalar data byte "+Arrays.toString(out)+'\n');
		return out;
	}
	
}
