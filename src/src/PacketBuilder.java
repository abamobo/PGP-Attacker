package src;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.io.ByteArrayInputStream;
import javax.swing.text.html.HTMLDocument.Iterator;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;


/*
 * this class is the whole packet, containg at the beginning only the needed subpackets (public key, user id , signature)
 * all other packets will be stripped
 */
//https://tools.ietf.org/html/rfc4880#section-11.1
/*
 * mimmal transferable public key:
 * one publickey packet
 * one user id package
 * one signature packet
 */
public class PacketBuilder {
	
	private byte[] data;
	private PubKeyPacket pubKey = null;
	private UserIDPacket userID = null;
	private SignaturePacket sig = null;
	private UserAttributePacket userAttr = null;
	
	private ArrayList<Byte> whole = new ArrayList<Byte>();
	private byte[] payl;
	private String payload;
	private Path inPath;
	private Path outPath;
	
	private MPI n; //TODO: delete me is currently used for rsa sig
	
	/*
	 * create new Packet
	 */
	public PacketBuilder(Path out, String payload){
		//clear tmp file
		Path path = FileSystems.getDefault().getPath("src", "tmp");
		clearFile(path);// TODO:remove comment
		//done clearing tmp file
		//clear out file
		clearFile(out); // TODO:remove comment
		//end clear out file;
		this.outPath = out;
		if (payload != ""){
			payl = Util.payload2Barr(payload);
			this.payload = payload;
		}
		else{
			FileUtil fu = new FileUtil(FileSystems.getDefault().getPath("src", "html5sec"));
			this.payl = fu.getBytesAt(0, (int) fu.getFileLength(FileSystems.getDefault().getPath("src", "html5sec")));
		}
	}
	
	public void clearFile(Path path){
		try {
			Files.write(path, new byte[0], StandardOpenOption.CREATE); // if not exist create
			Files.delete(path); //delete
			Files.write(path, new byte[0], StandardOpenOption.CREATE_NEW); // create newly
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void addSignaturePacket()  {
		//system.out.println("begin writing sig");
	//	sig = new SignaturePacket(SignatureTypes.POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET,PubKeyAlgos.DSA, this.payload);
		
		ArrayList<SignatureSubPacket> hashedSubPackets = new ArrayList<SignatureSubPacket>();
		ArrayList<SignatureSubPacket> UNhashedSubPackets = new ArrayList<SignatureSubPacket>();
		
		String p = this.payload;
		HashAlgorithms hashAlgo = HashAlgorithms.MD5;

		hashedSubPackets.add(new SignatureSubPacket(SigSubTypes.SIGNATURE_CREATION_TIME));
		hashedSubPackets.add(new SignatureSubPacket(SigSubTypes.KEY_FLAGS));
		hashedSubPackets.add(new SignatureSubPacket(SigSubTypes.KEY_EXPIRATION_TIME));
		hashedSubPackets.add(new SignatureSubPacket(SigSubTypes.PREFERRED_SYMMETRIC_ALGORITHMS));
		hashedSubPackets.add(new SignatureSubPacket(SigSubTypes.PREFERRED_HASH_ALGORITHMS));
		hashedSubPackets.add(new SignatureSubPacket(SigSubTypes.PREFERRED_COMPRESSION_ALGORITHMS));
		hashedSubPackets.add(new SignatureSubPacket(SigSubTypes.FEATURES));
		hashedSubPackets.add(new SignatureSubPacket(SigSubTypes.KEY_SERVER_PREFERENCES));
		//hashedSubPackets.add(new SignatureSubPacket(SigSubTypes.POLICY_URI,p, pubKey,  hashAlgo));
		
		//UNhashedSubPackets.add(new SignatureSubPacket(SigSubTypes.POLICY_URI,p ,pubKey,  hashAlgo));
		UNhashedSubPackets.add(new SignatureSubPacket(SigSubTypes.ISSUER,pubKey));
		
		
		MPI[] mpis = new MPI[2];
		mpis[0] = new MPI("asd");
		mpis[1] = new MPI("asd");
		
		//sig = new SignaturePacket(SignatureTypes.POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET,PubKeyAlgos.DSA, hashedSubPackets, UNhashedSubPackets,mpis);
		
		//rsa md5 signature
		//sig = new SignaturePacket2(SignatureTypes.POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET, hashedSubPackets, UNhashedSubPackets, this.n, new byte[4],this.userID);
		
		sig = new SignaturePacket(4,SignatureTypes.POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET, 
				PubKeyAlgos.RSA_ENC_OR_SIGN, HashAlgorithms.SHA1, hashedSubPackets, UNhashedSubPackets, 
				Util.payload2Barr("asd"), userID, pubKey);
		addPacket(sig.getWholePacket());
		System.out.println(Arrays.toString(sig.getWholePacket()));
		//System.out.println("end writing sig");
	}
	
	public void addPubKeyPacket(){

		//system.out.println("begin writing pubKey");
		MPI[] mpis = new MPI[2]; // TODO:richtige Payload
		//mpis[0] = new MPI("a");
		byte[] data = new byte[1];
		data[0] = 1;
		mpis[1] = new MPI(data);

		data = new byte[256];
		data[0] = (byte) 0xF;
		mpis[0] = new MPI(data);
		data = new byte[1];
		data[0] = (byte) 0x01;
		mpis[1] = new MPI(data);
		this.n = mpis[0];
		
		byte [] time = {1,2,3,4};
		byte[] expTime={1,2};
		this.pubKey = new PubKeyPacket(PubKeyAlgos.RSA_ENC_OR_SIGN, 4, mpis, time, expTime);
		addPacket(pubKey.readWholePacket());
		//system.out.println("end writing pubKey");
		
	}
	
	public byte[] overrideFingerprint(){
		try {
			Process process = new ProcessBuilder("gpg","--with-fingerprint","/home/ed/.gnupg/pubkey2.gpg").start();
			InputStream is = process.getInputStream();
			InputStreamReader isr = new InputStreamReader(is);
			BufferedReader br = new BufferedReader(isr);
			String line;

			//System.out.printf("Output of running %s is:", Arrays.toString(args));
			String fp="";
			while ((line = br.readLine()) != null ) {
				if (line.contains("fingerprint")){
					  fp = line;
					  break;
				}
			}
		//	System.out.println(fp);
			fp=fp.substring(fp.indexOf('=')+1, fp.length());
			
			 
			//System.out.println(fp);
			fp = fp.trim();
			//System.out.println(fp);
			fp = fp.replaceAll("\\s",""); //remove all whitespaces

			//System.out.println(fp);
			byte[] finger = new byte[20];
			int tmp, tmp2;
			for (int i=0; i<fp.length()-1; i += 2){
				tmp =  ( Character.digit(fp.charAt(i), 16) << 4);
				tmp2 =  ( Character.digit(fp.charAt(i+1), 16) );
				finger[i/2] = (byte) (tmp+tmp2);
				
				
			}
			pubKey.setFingerprint(finger);
			return finger;
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public void addSubPubKeyPacket(){
		//system.out.println("begin writing pubKey");
		MPI[] mpis = new MPI[2]; // TODO:richtige Payload
		mpis[0] = new MPI("a");
		mpis[1] = new MPI("aa");
		//mpis[1] = new MPI("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
		this.n = mpis[0];
		
		byte [] time = {1,2,3,4};
		byte[] expTime={1,2};
		SubKeyPacket subPubKey = new SubKeyPacket(PubKeyAlgos.RSA_ENC_OR_SIGN, 4, mpis, time, expTime);
		addPacket(subPubKey.readWholePacket());
		//system.out.println("end writing pubKey");
	}
	public void addUserIDPacket(){
		//system.out.println("begin writing useridPacket");
		userID = new UserIDPacket(this.payload);//TODO:change
		addPacket(userID.getWholePacket());
		//system.out.println("end writing useridPacket");
		
		//TODO info:
		/*
		 * after the user attribute package  gpg --with fingerprint will list the fingerprint
		 */
		overrideFingerprint();
	}
	
	public void addUserAttrPacket(String str, boolean standardPayload){
		//system.out.println("begin writing UserAttrPacket");
		userAttr = new UserAttributePacket(str, standardPayload);
		addPacket(userAttr.getWholePacket());

		//system.out.println("end writing UserAttrPacket");
	}

	public void addPacket(byte[] data){
		for ( int i=0; i<data.length; i++){
			this.whole.add(data[i]);
		}
		
		writeWhole2File();
	}
	
	public void armorPacket(){
		/*
		 * 1. read unarmored packet in
		 */
		
		FileUtil fu = new FileUtil(this.outPath);
		byte[] data = fu.getBytesAt(0, (int)FileUtil.getFileLength(this.outPath));
		/*
		 * armor
		 */
		String dat = Armor.toRadix64(data); data = null;
		char[] beginPGPPublicKeyBlock = {0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20, 0x50, 0x47, 0x50, 0x20, 0x50, 0x55, 0x42, 0x4C, 0x49, 0x43, 0x20, 0x4B, 0x45, 0x59, 0x20, 0x42, 0x4C, 0x4F, 0x43, 0x4B, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x0A, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x47, 0x6E, 0x75, 0x50, 0x47, 0x20, 0x76, 0x31, 0x0A, 0x0A};
		char[] endPGPPublicKeyBlock = {0x0A, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44, 0x20, 0x50, 0x47, 0x50, 0x20, 0x50, 0x55, 0x42, 0x4C, 0x49, 0x43, 0x20, 0x4B, 0x45, 0x59, 0x20, 0x42, 0x4C, 0x4F, 0x43, 0x4B, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x0A};
		
		
		dat = new String(beginPGPPublicKeyBlock)+
			  dat+
			  new String(endPGPPublicKeyBlock);
		data = Util.payload2Barr(dat);
		/*
		 * write to file
		 */
		fu.clearFile();
		fu.AppendChunk(data);
	}
	
	/*private byte[] enArmor(byte[] data){
		String dat = Armor.toRadix64(data);
		char[] beginPGPPublicKeyBlock = {0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20, 0x50, 0x47, 0x50, 0x20, 0x50, 0x55, 0x42, 0x4C, 0x49, 0x43, 0x20, 0x4B, 0x45, 0x59, 0x20, 0x42, 0x4C, 0x4F, 0x43, 0x4B, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x0A, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x47, 0x6E, 0x75, 0x50, 0x47, 0x20, 0x76, 0x31, 0x0A, 0x0A};
		char[] endPGPPublicKeyBlock = {0x0A, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44, 0x20, 0x50, 0x47, 0x50, 0x20, 0x50, 0x55, 0x42, 0x4C, 0x49, 0x43, 0x20, 0x4B, 0x45, 0x59, 0x20, 0x42, 0x4C, 0x4F, 0x43, 0x4B, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x0A};
		
		
		dat = new String(beginPGPPublicKeyBlock)+
			  dat+
			  new String(endPGPPublicKeyBlock);
		data = Util.payload2Barr(dat);
		return data;
	}*/
	
	public void writeWhole2File(){
		readFromTmpFile();
		//system.out.println("writing file to disk");
		Path path =  this.outPath;
		byte[] data = this.getWholePacket();
		//system.out.println(path == null);
		try {
			Files.write(path, data, StandardOpenOption.APPEND);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//system.out.println("clearing whole after write");
		this.whole = new ArrayList<Byte>();
		//system.out.println("done");
		//system.out.println("done");
	}
	
	private void write2TmpFile(){
		Path path = FileSystems.getDefault().getPath("src", "tmp");
		
		byte[] data = this.getWholePacket();
		
		whole = new ArrayList<Byte>(); // clear packet array List
		
		try {
			Files.write(path, data, StandardOpenOption.APPEND);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private void readFromTmpFile(){
		
		Path path = FileSystems.getDefault().getPath("src", "tmp");
		try {
			byte[] fileData;
			fileData = Files.readAllBytes(path);
			for(int i=0; i< fileData.length; i++){
				whole.add(fileData[i]);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
		
	public void readFilein(){
		/*
		 * read packet data from file
		 */
		try {
			byte[] fileData;
			fileData = Files.readAllBytes(this.inPath);
			for(int i=0; i< fileData.length; i++){
				whole.add(fileData[i]);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	/*
	 * returns the size of the whole package
	 */
	public int getSize(){
		return whole.size();
	}
	
	public Path getOutPath() {
		return outPath;
	}
	public void setOutPath(Path outPath) {
		this.outPath = outPath;
	}
	public byte[] getWholePacket(){
		byte[] out = new byte[this.whole.size()];
		for (int i=0; i<this.whole.size();i++){
			out[i] = this.whole.get(i);
		}
		return out;
	}
}