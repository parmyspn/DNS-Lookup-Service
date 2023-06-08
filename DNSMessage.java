package ca.ubc.cs.cs317.dnslookup;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;

public class DNSMessage {
    public static final int MAX_DNS_MESSAGE_LENGTH = 512;

    // The offset into the message where the header ends and the data begins.
    public final static int DataOffset = 12;

    // Opcode for a standard query
    public final static int QUERY = 0;



    /**
     * TODO:  You will add additional constants and fields
     */
    private final ByteBuffer buffer;
    private final HashMap<String,Integer> nameMap;



    /**
     * Initializes an empty DNSMessage with the given id.
     *
     * @param id The id of the message.
     */
    public DNSMessage(short id) {
        this.nameMap = new HashMap<>();
        this.buffer = ByteBuffer.allocate(MAX_DNS_MESSAGE_LENGTH);
        // TODO: Complete this method
        this.buffer.putShort(id);
        buffer.position(12);

    }

    /**
     * Initializes a DNSMessage with the first length bytes of the given byte array.
     *
     * @param recvd The byte array containing the received message
     * @param length The length of the data in the array
     */
    public DNSMessage(byte[] recvd, int length) {
        this.nameMap = new HashMap<>();
        buffer = ByteBuffer.wrap(recvd, 0, length);
        // TODO: Complete this method
        buffer.position(12);
    }

    /**
     * Getters and setters for the various fixed size and fixed location fields of a DNSMessage
     * TODO:  They are all to be completed
     */
    public int getID() {
        return buffer.getShort(0) & 0x0000ffff;
    }

    public void setID(int id) {
        buffer.putShort(0,(short)(id&0x0000ffff));
    }

    public boolean getQR() {
        byte b = buffer.get(2);
        return (b&0x80) >> 7 == 1;
    }

    public void setQR(boolean qr) {
        Byte b = buffer.get(2);
        if(qr){
            b = (byte) (b | 0x80);
        }else{
            b = (byte) (b & 0x7F);
        }
        buffer.put(2,b);

    }

    public boolean getAA() {
        Byte b = buffer.get(2);
        return (b & 0x04) >> 2 == 1;

    }

    public void setAA(boolean aa) {
        Byte b = buffer.get(2);
        if(aa){
            b = (byte) (b | 0x04);
        }else{
            b = (byte) (b & 0xFb);
        }
        buffer.put(2,b);
    }

    public int getOpcode() {
        Byte b = buffer.get(2);
        return ((byte) (b&0x78)) >> 3 & 0x000000ff;

    }
    public void printByte(int index){
        byte b = buffer.get(index);
        System.out.println(String.format("%8s", Integer.toBinaryString(Byte.toUnsignedInt(b))).replace(' ','0'));
    }
    public void setOpcode(int opcode) {
        Byte b = buffer.get(2);
        Byte opc =(byte)((( opcode))<< 3);
        b = (byte) ((b & 0x87) |opc);
        buffer.put(2,b);
    }

    public boolean getTC() {
        Byte b = buffer.get(2);
        return (b & 0x02) >> 1 == 1;
    }

    public void setTC(boolean tc) {
        Byte b = buffer.get(2);
        //printByte(2);
        if(tc){
            b = (byte) (b | 0x02);
        }else{
            b = (byte) (b & 0xFd);
        }
        buffer.put(2,b);
    }

    public boolean getRD() {
        Byte b = buffer.get(2);
        return (b & 0x01)  == 1;
    }

    public void setRD(boolean rd) {
        Byte b = buffer.get(2);
        if(rd){
            b = (byte) (b | 0x01);
        }else{
            b = (byte) (b & 0xFe);
        }
        buffer.put(2,b);
    }

    public boolean getRA() {
        Byte b = buffer.get(3);
        return (b & 0x80) >> 7  == 1;
    }

    public void setRA(boolean ra) {
        Byte b = buffer.get(3);
        if(ra){
            b = (byte) (b | 0x80);
        }else{
            b = (byte) (b & 0x7F);
        }
        buffer.put(3,b);
    }

    public int getRcode() {
        Byte b = buffer.get(3);
        return (b & 0x0f) ;
    }

    public void setRcode(int rcode) {
        Byte b = buffer.get(3);
        Byte code = (byte)(rcode & 0x0f );
        b = (byte) ((b & 0xf0)|code);
        buffer.put(3,b);
    }

    public int getQDCount() {
        return buffer.getShort(4) & 0x0000ffff;
    }

    public void setQDCount(int count) {
        buffer.putShort(4,(short)count);

    }

    public int getANCount() {
        return buffer.getShort(6) & 0x0000ffff;
    }
    public void setANCount(int count) {
        buffer.putShort(6,(short)count);

    }

    public int getNSCount() {
        return buffer.getShort(8) & 0x0000ffff;
    }

    public void setNSCount(int count) {
        buffer.putShort(8,(short)count);
    }

    public int getARCount() {
        return  buffer.getShort(10) & 0x0000ffff;
    }

    public void setARCount(int count) {
        buffer.putShort(10,(short)count);
    }

    /**
     * Return the name at the current position() of the buffer.
     *
     * The encoding of names in DNS messages is a bit tricky.
     * You should read section 4.1.4 of RFC 1035 very, very carefully.  Then you should draw a picture of
     * how some domain names might be encoded.  Once you have the data structure firmly in your mind, then
     * design the code to read names.
     *
     * @return The decoded name
     */

    public String getName() {
        // TODO: Complete this method

        String result = "";
        int pos = buffer.get() & 0xff;
        int saved = 0;
        if (pos == 0) {
            return "";
        }
        if ((pos & 0xc0) == 0xc0) {
            //printByte(buffer.position());
            int offset = (((buffer.get() & 0xff) | (pos & 0x3f) << 8));
            saved = buffer.position();
            buffer.position(offset);
            result = getName();
        } else {
            byte[] name = new byte[pos];
            buffer.get(name, 0, pos);
            String str = new String(name);
            String endSub = getName();

            if (endSub.equals("")) {
                result = str;
            } else {
                result = str + "." + endSub;
            }
        }
        if(saved != 0 ){
            buffer.position(saved);
        }
        return result;
    }

    /**
     * The standard toString method that displays everything in a message.
     * @return The string representation of the message
     */
    public String toString() {
        // Remember the current position of the buffer so we can put it back
        // Since toString() can be called by the debugger, we want to be careful to not change
        // the position in the buffer.  We remember what it was and put it back when we are done.
        int end = buffer.position();
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("ID: ").append(getID()).append(' ');
            sb.append("QR: ").append(getQR() ? "Response" : "Query").append(' ');
            sb.append("OP: ").append(getOpcode()).append(' ');
            sb.append("AA: ").append(getAA()).append('\n');
            sb.append("TC: ").append(getTC()).append(' ');
            sb.append("RD: ").append(getRD()).append(' ');
            sb.append("RA: ").append(getRA()).append(' ');
            sb.append("RCODE: ").append(getRcode()).append(' ')
                    .append(dnsErrorMessage(getRcode())).append('\n');
            sb.append("QDCount: ").append(getQDCount()).append(' ');
            sb.append("ANCount: ").append(getANCount()).append(' ');
            sb.append("NSCount: ").append(getNSCount()).append(' ');
            sb.append("ARCount: ").append(getARCount()).append('\n');
            buffer.position(DataOffset);
            showQuestions(getQDCount(), sb);
            showRRs("Authoritative", getANCount(), sb);
            showRRs("Name servers", getNSCount(), sb);
            showRRs("Additional", getARCount(), sb);
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "toString failed on DNSMessage";
        }
        finally {
            buffer.position(end);
        }
    }

    /**
     * Add the text representation of all the questions (there are nq of them) to the StringBuilder sb.
     *
     * @param nq Number of questions
     * @param sb Collects the string representations
     */
    private void showQuestions(int nq, StringBuilder sb) {
        sb.append("Question [").append(nq).append("]\n");
        for (int i = 0; i < nq; i++) {
            DNSQuestion question = getQuestion();
            sb.append('[').append(i).append(']').append(' ').append(question).append('\n');
        }
    }

    /**
     * Add the text representation of all the resource records (there are nrrs of them) to the StringBuilder sb.
     *
     * @param kind Label used to kind of resource record (which section are we looking at)
     * @param nrrs Number of resource records
     * @param sb Collects the string representations
     */
    private void showRRs(String kind, int nrrs, StringBuilder sb) {
        sb.append(kind).append(" [").append(nrrs).append("]\n");
        for (int i = 0; i < nrrs; i++) {
            ResourceRecord rr = getRR();
            sb.append('[').append(i).append(']').append(' ').append(rr).append('\n');
        }
    }

    /**
     * Decode and return the question that appears next in the message.  The current position in the
     * buffer indicates where the question starts.
     *
     * @return The decoded question
     */
    public DNSQuestion getQuestion() {
        // TODO: Complete this method
        String name = this.getName();
        RecordType type = RecordType.getByCode(buffer.getShort()&0x0000ffff);
        RecordClass recordClass = RecordClass.getByCode(buffer.getShort()&0x0000ffff);
        return new DNSQuestion(name, type,recordClass);


    }

    /**
     * Decode and return the resource record that appears next in the message.  The current
     * position in the buffer indicates where the resource record starts.
     *
     * @return The decoded resource record
     */
    public ResourceRecord getRR() {
        // TODO: Complete this method
        DNSQuestion q = getQuestion();
        int ttl = buffer.getInt();
        short rdLen = buffer.getShort();
        RecordType type = q.getRecordType();
        try{
            String name;
            if (type == RecordType.A || type == RecordType.AAAA) {
                byte[] hostName= new byte[rdLen];
                buffer.get(hostName, 0, rdLen);
                return new ResourceRecord(q, ttl, InetAddress.getByAddress(hostName));
            } else if (type == RecordType.MX) {
                buffer.getShort();
                name = getName();
                return new ResourceRecord(q, ttl, name);
                
            }else{
                name = getName();
                return new ResourceRecord(q, ttl, name);
            }

        }catch(Exception exp){
            return new ResourceRecord(q, ttl, "");
        }
    }

    /**
     * Helper function that returns a hex string representation of a byte array. May be used to represent the result of
     * records that are returned by a server but are not supported by the application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    public static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }
    /**
     * Helper function that returns a byte array from a hex string representation. May be used to represent the result of
     * records that are returned by a server but are not supported by the application (e.g., SOA records).
     *
     * @param hexString a string containing the hex value of every byte in the data.
     * @return data a byte array containing the record data.
     */
    public static byte[] hexStringToByteArray(String hexString) {
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            String s = hexString.substring(i * 2, i * 2 + 2);
            bytes[i] = (byte)Integer.parseInt(s, 16);
        }
        return bytes;
    }

    /**
     * Add an encoded name to the message. It is added at the current position and uses compression
     * as much as possible.  Make sure you understand the compressed data format of DNS names.
     *
     * @param name The name to be added
     */
    public void addName(String name) {
        // TODO: Complete this method
        int i = 0;
        String sub = name;
        int nextPoint;
        while(i < name.length()){
            sub = sub.substring(i);
            if(!nameMap.containsKey(sub)){
                nameMap.put(sub,buffer.position());
                nextPoint = sub.indexOf(".");
                i = (nextPoint == -1 )?  name.length() +1: nextPoint + 1;
                String word = sub.split("\\.")[0];
                int len = word.length();
                buffer.put((byte)(len & 0x000000ff));
                for(int j = 0 ; j< len; j++){
                    buffer.put((byte)word.charAt(j));
                }
            }
            else{
                int a = nameMap.get(sub);
                int pointer = a | 0xc000;;
                buffer.putShort((short)pointer);
                return;
            }
        }
        buffer.put((byte)(0x00));
    }

    /**
     * Add an encoded question to the message at the current position.
     * @param question The question to be added
     */
    public void addQuestion(DNSQuestion question) {
        // TODO: Complete this method
        if(this.getANCount() == 0 && this.getNSCount()==0){
            this.setQDCount(this.getQDCount() + 1);
            addName(question.getHostName());
            addQType(question.getRecordType());
            addQClass(question.getRecordClass());
            //setQDCount(getQDCount()+1);
        }
    }

    /**
     * Add an encoded resource record to the message at the current position.
     * The record is added to the additional records section.
     * @param rr The resource record to be added
     */
    public void addResourceRecord(ResourceRecord rr) {
        addResourceRecord(rr, "additional");
    }

    /**
     * Add an encoded resource record to the message at the current position.
     *
     * @param rr The resource record to be added
     * @param section Indicates the section to which the resource record is added.
     *                It is one of "answer", "nameserver", or "additional".
     */
    public void addResourceRecord(ResourceRecord rr, String section) {
        // TODO: Complete this method
        if(section.equals("answer")){
            setARCount(getARCount()+1);
        } else if (section.equals("nameserver")) {
            setNSCount(getNSCount()+1);
        } else if (section.equals("additional")) {
            setARCount(getARCount()+1);
        }
        String name = rr.getHostName();
        addName(name);
        RecordType type = rr.getRecordType();
        addQType(type);
        addQClass(rr.getRecordClass());
        buffer.putInt((int)rr.getRemainingTTL());
        if (type == RecordType.A || type == RecordType.AAAA) {
            try {
                this.buffer.putShort((short) rr.getInetResult().getAddress().length);
                this.buffer.put(rr.getInetResult().getAddress());
            } catch (Exception e) {
                System.out.println("Inet Address Failed");
            }

        } else {
            this.buffer.putShort((short) rr.getTextResult().length());
            if (type == RecordType.MX) {
                this.buffer.putShort((short) 1);
            }
            addName(rr.getTextResult());
        }

    }

    /**
     * Add an encoded type to the message at the current position.
     * @param recordType The type to be added
     */
    private void addQType(RecordType recordType) {
        // TODO: Complete this method
        buffer.putShort((short)recordType.getCode());
        //buffer.position(buffer.position()+2);

    }

    /**
     * Add an encoded class to the message at the current position.
     * @param recordClass The class to be added
     */
    private void addQClass(RecordClass recordClass) {
        // TODO: Complete this method
        buffer.putShort((short)recordClass.getCode());
        //buffer.position(buffer.position()+2);

    }

    /**
     * Return a byte array that contains all the data comprising this message.  The length of the
     * array will be exactly the same as the current position in the buffer.
     * @return A byte array containing this message's data
     */
    public byte[] getUsed() {
        // TODO: Complete this method
        byte[] used = new byte[buffer.position()];
        for(int i = 0 ; i < buffer.position(); i++){
            used[i] = buffer.get(i);
        }
        return used;
    }

    /**
     * Returns a string representation of a DNS error code.
     *
     * @param error The error code received from the server.
     * @return A string representation of the error code.
     */
    public static String dnsErrorMessage(int error) {
        final String[] errors = new String[]{
                "No error", // 0
                "Format error", // 1
                "Server failure", // 2
                "Name error (name does not exist)", // 3
                "Not implemented (parameters not supported)", // 4
                "Refused" // 5
        };
        if (error >= 0 && error < errors.length)
            return errors[error];
        return "Invalid error message";
    }
}
