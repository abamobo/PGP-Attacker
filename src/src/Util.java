package src;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.Arrays;


public class Util {
	
	public static void printByteArr(byte[] arr){
		
		System.out.print("0x");
		for (int i=0; i<arr.length;i++){
			String tmp = (Integer.toHexString(( arr[i]< 0 ? arr[i] & 0xFF: arr[i] )));
			System.out.print( (tmp.length() < 2 ? "0"+tmp : tmp) +" ");
		}
		System.out.println("");
	}
	public static String ByteArr2String(byte[] arr){
		String out = "";
		for (int i=0; i<arr.length;i++){
			String tmp = (Integer.toHexString(( arr[i]< 0 ? arr[i] & 0xFF: arr[i] )));
			out += (tmp.length() < 2 ? "0"+tmp : tmp) +" ";
		}
		return out;
	}
	
	public static String[] splitPayloadforMPI(String payload){
		//splits payload after MPI.MAX_SIZE characters
		String regex = "(?<=\\G.{"+MPI.MAX_SIZE+"})";
		return payload.split(regex);
	}
	public static String readPayloads(){
		String out = "";
		
		File file = new File("src/html5sec");
		File file2 = new File("src/xmlcheatsheet");
		
		try {
			out =  Files.readAllLines(file.toPath() ,Charset.defaultCharset()).toString();
			out += Files.readAllLines(file2.toPath(),Charset.defaultCharset()).toString();
		} catch (IOException e) {
			System.err.println("error reading payload files in");
			e.printStackTrace();
		}
		
		return out;
	}
	
	/*
	 * long -> Byte[]
	 */
	static byte[] to2Bytes(long inp){
		
		byte[] out = new byte[2];
		out[0] = (byte) (inp >> 8);
		out[1] = (byte) (inp >> 0);
		
	  return out;
	}
	static byte[] to4Bytes(long inp){
		
		byte[] out = new byte[4];
		out[3] = (byte) (inp >> 24);
		out[2] = (byte) (inp >> 16);
		out[0] = (byte) (inp >> 8);
		out[1] = (byte) (inp >> 0);

	  return out;
	}
	
	public static int getUnsignedByte(byte b){
		if (b < 0){
			return (byte) (b & 0xFF);
		}else{
			return b ;
		}
	}
	public static int getUnisgnedByteAt(byte[] arr, int offset){
		return getUnsignedByte(arr[offset]);
	}
	
	public static int byteAt(int index, byte[] data){
		return (data[index] & 0xFF);
	}
	
	
	public static byte[] payload2Barr(String payload){
		//https://tools.ietf.org/html/rfc4880#section-3.4
		//Unless otherwise specified, the character set for text is the UTF-8
		
		/*
		 * TODO: problem size increases after utf-8 encoding, however a bigger payload is problematic since th data size restrictions on MPIs
		 */
		byte[] out;
		out = payload.getBytes(Charset.forName("UTF-8"));
		/*try {
			out = payload.getBytes("UTF-8BE");
			return out;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}*/
		return out;
		//byte[] aout = new byte[payload.length()];
	//	//System.out.println(Arrays.toString(out));
		//System.out.println(Arrays.toString(aout));
		//System.out.println(MPI.MAX_SIZE);
		//System.arraycopy(out, 0, aout, 0, payload.length());
		//return aout;
	}
	
	/*
	 * prints a byte in binary form: 76543210
	 */
	public static void printByte2Bin(byte num){
		for (int i =7; i>=0;i--){
			if (Util.isBitSet(num,i)){
				System.out.print('1');
			}
			else{
				System.out.print('0');
			}
		}
		System.out.println();
	}
	/*
	 * Set a bit at position pos
	 * 
	 * @param
	 */
	public byte setBit(byte b, int pos){
		return (byte) (b | (1 << pos));
	}
	
	/*
	 * Clear a bit at position pos
	 * 
	 * @param
	 */
	public byte clearBit(byte b, int pos){
		return (byte) (b & ~(1 << pos));
	}
	
	/*
	 * Get Bit at position pos
	 * @param: pos the position in one byte form of the byte: 76543210
	 */
	public static boolean isBitSet (byte b, int pos){
		if ( ((byte) b & (1<<pos))  > 0){
			return true;
		}
		else {
			return false;
		}
	}
	/* pos2 has to be greater than pos1
	 * example get Bits 5-2 from 11101000(bin) -> 1010(bin) = 10(dec)
	 */
	public static byte getSubSetOfBits(byte b, int pos2, int pos1){
		byte sum = 0;
		if (pos2 < pos1){ // swap pos1, pos2
			int tmp = pos2;
			pos2= pos1;
			pos1 = tmp;
		}
		for (int i=pos2; i>=pos1;i--){
			if (isBitSet(b,i)){
				sum += Math.pow(2, i-pos1);
			}
		}
		return sum;
	}
	
	/*
	 * sums of the values of all bits between pos 1 and  pos 2 byte format: 76543210
	 * example byte  = 01011011, sum from 2 to 4 is: 0*2**2+1*2**3+1*2**4
	 */
	/*public static byte getSumOfBits(byte b, int pos1, int pos2){
		byte sum = 0;
		if (pos1 < pos2){
			int tmp = pos2;
			pos2= pos1;
			pos1 = tmp;
		}
		for (int i=pos2; i<=pos1;i++){
			if (isBitSet(b,i)){
				sum += Math.pow(2, i);
			}
		}
		return sum;
	}*/
	
	/**
     * Convert a byte array of 8 bit characters into a String.
     * 
     * @param bytes the array containing the characters
     * @param length the number of bytes to process
     * @return a String representation of bytes
     */
    public String toString(
        byte[] bytes,
        int    length)
    {
        char[]	chars = new char[length];
        
        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(bytes[i] & 0xff);
        }
        
        return new String(chars);
    }
    
    /**
     * Convert a byte array of 8 bit characters into a String.
     * 
     * @param bytes the array containing the characters
     * @return a String representation of bytes
     */
    public String toString(
        byte[]	bytes)
    {
        return toString(bytes, bytes.length);
    }
    /**
     * Convert the passed in String to a byte array by
     * taking the bottom 8 bits of each character it contains.
     * 
     * @param string the string to be converted
     * @return a byte array representation
     */
    public byte[] toByteArray(
        String string)
    {
        byte[]	bytes = new byte[string.length()];
        char[]  chars = string.toCharArray();
        
        for (int i = 0; i != chars.length; i++)
        {
            bytes[i] = (byte)chars[i];
        }
        
        return bytes;
    }
}
