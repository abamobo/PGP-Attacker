package src;

public class SubKeyPacket extends PubKeyPacket{

	public SubKeyPacket(PubKeyAlgos keyType, int version, MPI[] mpis,
			byte[] time, byte[] expirationTime) {
		super(keyType, version, mpis, time, expirationTime);
		//difference to pubkey is tag
		//so only changing the header is sufficient (and the whole package)
		head = new Header(PacketTags.PUB_SUB_KEY,head.getBodyLen());
		this.wholePacket[0] = PacketTags.PUB_SUB_KEY.getNum();//TODO: change to whole, when pubkey is also updated to use whole
	}
	
	
	
}
