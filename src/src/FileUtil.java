package src;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;



/*
 * this class reads,writes chuncks of data to the ouput file
 * this class is neccessary because holding the whole file inside memory would be to memory consuming
 * so this class is used to write an array after a certain num of bytes to the spcified file
 * the writing to the file will happen after 50Megabyte (50*10**6) 
 */
public class FileUtil {
	
	public final static long MAX_ARR_SIZE = 50000000L;

	static Path path;
	
	public FileUtil(Path p){
		
		FileUtil.path = p;
		
	}
	public void setPath(){
		
	}
	
	/*
	 * if the file does not exist it will be created
	 * if it exists, nothing happens
	 */
	public boolean createFile(){
		try {
			Files.write(path, new byte[0], StandardOpenOption.CREATE);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		return true;
	}
	/*
	 * gets the number of bytes inside a file
	 * on failure return -1
	 */
	public static long getFileLength(Path path){
		long len;
		
		RandomAccessFile raf;
		try {
			raf = new RandomAccessFile(path.toFile(), "r");
			len = raf.length();
			raf.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			len = -1;
		} catch (IOException e) {
			e.printStackTrace();
			len = -1;
		}
		
		
		return len;
	}
	/*
	 * empties the content of a file, on failure returns false
	 */
	public boolean clearFile(){
		boolean success = true;
		try {
			RandomAccessFile raf = new RandomAccessFile(this.path.toFile(),"rw");
			raf.setLength(0);
			raf.close();
		} catch (FileNotFoundException e1) {			
			e1.printStackTrace();
			success = false;
		} catch (IOException e) {
			e.printStackTrace();
			success = false;
		}
		
		return success;
	}
	
	/*
	 * appends the byte array provided to the specified path,
	 * on en error this method returns false
	 */
	public boolean AppendChunk(byte[] data){
		boolean success = true;
		try {
			Files.write(path, data, StandardOpenOption.APPEND);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			success = false;
		}
		
		return success;
	}
	/*
	 * appends the byte arraylist provided to the specified path,
	 * on en error this method returns false
	 */
	public boolean AppendChunk(ArrayList<Byte> data){
		boolean success = true;
		byte[] dat = new byte[data.size()];
		for (int i=0; i<data.size();i++){
			dat[i] = data.get(i);
		}
		try {
			Files.write(path, dat, StandardOpenOption.APPEND);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			success = false;
		}
		
		return success;
	}
	
	/*
	 * read at offset, len Bytes and return as array
	 * if anything fails null is returned
	 */
	public byte[] getBytesAt(int offset, int len){
		byte[] out = new byte[len];
		try {
			RandomAccessFile raf = new RandomAccessFile(this.path.toFile(),"rw");
			raf.seek(offset);
			raf.read(out);
			raf.close();
		} catch (FileNotFoundException e1) {			
			e1.printStackTrace();
			out = null;
		} catch (IOException e) {
			e.printStackTrace();
			out = null;
		}
		return out;
	}
	
	/*
	 * read at offset, len Byte and return as array
	 * if anything fails null is returned
	 */
	public byte getByteAt(int offset){
		byte[] out = new byte[1];
		try {
			RandomAccessFile raf = new RandomAccessFile(this.path.toFile(),"rw");
			raf.seek(offset);
			raf.read(out);
			raf.close();
		} catch (FileNotFoundException e1) {			
			e1.printStackTrace();
			out = null;
		} catch (IOException e) {
			e.printStackTrace();
			out = null;
		}
		return out[0];
	}
	
	/*
	 * write the byte array data at the offset in the file
	 * returns false on failure
	 */
	public boolean replaceBytesAt(int offset, byte data[]){
		boolean success = true;
		
		
		try {
			RandomAccessFile raf = new RandomAccessFile(this.path.toFile(),"rw");
			raf.seek(offset);
			raf.write(data);
			raf.close();
		} catch (FileNotFoundException e1) {			
			e1.printStackTrace();
			success = false;
		} catch (IOException e) {
			e.printStackTrace();
			success = false;
		}
		
		return success;
	}
	
	/*
	 * writes the byte data at the offset in the file
	 * returns false on failure
	 */
	public boolean replaceByteAt(long offset, byte data){
		boolean success = true;
		
		try {
			RandomAccessFile raf = new RandomAccessFile(this.path.toFile(),"rw");
			raf.seek(offset);
			raf.writeByte(data);
			raf.close();
		} catch (FileNotFoundException e1) {			
			e1.printStackTrace();
			success = false;
		} catch (IOException e) {
			e.printStackTrace();
			success = false;
		}
		
		return success;
	}
	
}
