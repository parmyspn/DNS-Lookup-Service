package ca.ubc.cs.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.util.*;

public class DNSLookupService {

    public static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL_NS = 10;
    private static final int MAX_QUERY_ATTEMPTS = 3;
    private static final int MAX_DNS_MESSAGE_LENGTH = 512;
    private static final int SO_TIMEOUT = 5000;

    private final DNSCache cache = DNSCache.getInstance();
    private final Random random = new Random();
    private final DNSVerbosePrinter verbose;
    private final DatagramSocket socket;

    /**
     * Creates a new lookup service. Also initializes the datagram socket object with a default timeout.
     *
     * @param verbose    A DNSVerbosePrinter listener object with methods to be called at key events in the query
     *                   processing.
     * @throws SocketException      If a DatagramSocket cannot be created.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public DNSLookupService(DNSVerbosePrinter verbose) throws SocketException, UnknownHostException {
        this.verbose = verbose;
        socket = new DatagramSocket();
        socket.setSoTimeout(SO_TIMEOUT);
    }

    /**
     * Closes the lookup service and related sockets and resources.
     */
    public void close() {
        socket.close();
    }

    /**
     * Examines a set of resource records to see if any of them are an answer to the given question.
     *
     * @param rrs       The set of resource records to be examined
     * @param question  The DNS question
     * @return          true if the collection of resource records contains an answer to the given question.
     */
    private boolean containsAnswer(Collection<ResourceRecord> rrs, DNSQuestion question) {
        for (ResourceRecord rr : rrs) {
            if (rr.getQuestion().equals(question) && rr.getRecordType() == question.getRecordType()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Finds all the results for a specific question. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are retrieved recursively for new records of the same type, and the returning set will contain both the
     * CNAME record and the resulting resource records of the indicated type.
     *
     * @param question             Host and record type to be used for search.
     * @param maxIndirectionLevels Number of CNAME indirection levels to support.
     * @return A set of resource records corresponding to the specific query requested.
     * @throws DNSErrorException If the number CNAME redirection levels exceeds the value set in
     *                           maxIndirectionLevels.
     */
    public Collection<ResourceRecord> getResultsFollowingCNames(DNSQuestion question, int maxIndirectionLevels)
            throws DNSErrorException {

        if (maxIndirectionLevels < 0) throw new DNSErrorException("CNAME indirection limit exceeded");

        Collection<ResourceRecord> directResults = iterativeQuery(question);
        if (containsAnswer(directResults, question)) {
            return directResults;
        }

        Set<ResourceRecord> newResults = new HashSet<>();
        for (ResourceRecord record : directResults) {
            newResults.add(record);
            if (record.getRecordType() == RecordType.CNAME) {
                newResults.addAll(getResultsFollowingCNames(
                        new DNSQuestion(record.getTextResult(), question.getRecordType(), question.getRecordClass()),
                        maxIndirectionLevels - 1));
            }
        }
        return newResults;
    }

    /**
     * Answers one question.  If there are valid (not expired) results in the cache, returns these results.
     * Otherwise it chooses the best nameserver to query, retrieves results from that server
     * (using individualQueryProcess which adds all the results to the cache) and repeats until either:
     *   the cache contains an answer to the query, or
     *   the cache contains an answer to the query that is a CNAME record rather than the requested type, or
     *   every "best" nameserver in the cache has already been tried.
     *
     *  @param question Host name and record type/class to be used for the query.
     */
    public Collection<ResourceRecord> iterativeQuery(DNSQuestion question)
            throws DNSErrorException {
        Set<ResourceRecord> ans = new HashSet<>();
        Collection<ResourceRecord> results = cache.getCachedResults(question);
        if(!results.isEmpty()) return results;
        //DNSQuestion cnameQ = new DNSQuestion(question.getHostName(),RecordType.CNAME,question.getRecordClass());
        while(true){
            results = cache.getCachedResults(question);
            if(!results.isEmpty()) return results;
            List<ResourceRecord> records = cache.getBestNameservers(question);
            List<ResourceRecord> bestNS = cache.filterByKnownIPAddress(records);
            if(bestNS.isEmpty()){
                for(ResourceRecord rr : records){
                    DNSQuestion q = new DNSQuestion(rr.getTextResult(),RecordType.A,rr.getQuestion().getRecordClass());
                    bestNS.addAll(iterativeQuery(q));
                }
            }
            for (ResourceRecord nextNS : bestNS) {
                ans = individualQueryProcess(question, nextNS.getInetResult());
                if (!ans.isEmpty()) {
                    break;
                }
            }

        }

    }


    /**
     * Handles the process of sending an individual DNS query with a single question. Builds and sends the query (request)
     * message, then receives and parses the response. Received responses that do not match the requested transaction ID
     * are ignored. If no response is received after SO_TIMEOUT milliseconds, the request is sent again, with the same
     * transaction ID. The query should be sent at most MAX_QUERY_ATTEMPTS times, after which the function should return
     * without changing any values. If a response is received, all of its records are added to the cache.
     * <p>
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     * <p>
     * The method verbose.printQueryToSend() must be called every time a new query message is about to be sent.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the query.
     * @return If no response is received, returns null. Otherwise, returns a set of all resource records
     * received in the response.
     * @throws DNSErrorException if the Rcode in the response is non-zero
     */
    public Set<ResourceRecord> individualQueryProcess(DNSQuestion question, InetAddress server)
            throws DNSErrorException {
        /* TODO: To be implemented by the student */

        DNSMessage message = buildQuery(question);
        byte[] buf = new byte[MAX_DNS_MESSAGE_LENGTH];
        byte[] msgBuf = message.getUsed();
        DNSMessage recvMsg = null;
        int count = 0;
        while(count<MAX_QUERY_ATTEMPTS){
            verbose.printQueryToSend(question,server, message.getID());
            DatagramPacket packet = new DatagramPacket(msgBuf, msgBuf.length, server, DEFAULT_DNS_PORT);
            try {
                socket.send(packet);
            }catch(Exception err) {
                err.printStackTrace();
            }
            packet = new DatagramPacket(buf, buf.length);
            try{
                socket.receive(packet);
                byte[] recvBuf = packet.getData();
                recvMsg = new DNSMessage(recvBuf,recvBuf.length);
                if(recvMsg.getID() == message.getID() && recvMsg.getQR() ) {
                    break;
                }
            }catch(SocketTimeoutException e){
                count++;
            }catch(IOException e) {
                e.printStackTrace();
            }
        }
        if(recvMsg != null && recvMsg.getID() == message.getID() && recvMsg.getQR()) {
            return this.processResponse(recvMsg);
        }
        return null;
    }

    /**
     * Creates a DNSMessage containing a DNS query.
     * A random transaction ID must be generated and filled in the corresponding part of the query. The query
     * must be built as an iterative (non-recursive) request for a regular query with a single question. When the
     * function returns, the message's buffer's position (`message.buffer.position`) must be equivalent
     * to the size of the query data.
     *
     * @param question    Host name and record type/class to be used for the query.
     * @return The DNSMessage containing the query.
     */
    public DNSMessage buildQuery(DNSQuestion question) {
        /* TODO: To be implemented by the student */
        DNSMessage query = new DNSMessage((short)(random.nextInt() & 0x0000ffff));
        query.setQR(false);
        query.addQuestion(question);
        query.setOpcode(0);
        query.setQDCount(1);
        query.setARCount(0);
        query.setNSCount(0);
        query.setANCount(0);
        return query;
    }

    /**
     * Parses and processes a response received by a nameserver.
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     * Adds all resource records found in the response message to the cache.
     * Calls methods in the verbose object at appropriate points of the processing sequence. Must be able
     * to properly parse records of the types: A, AAAA, NS, CNAME and MX (the priority field for MX may be ignored). Any
     * other unsupported record type must create a record object with the data represented as a hex string (see method
     * byteArrayToHexString).
     *
     * @param message The DNSMessage received from the server.
     * @return A set of all resource records received in the response.
     * @throws DNSErrorException if the Rcode value in the reply header is non-zero
     */
    public Set<ResourceRecord> processResponse(DNSMessage message) throws DNSErrorException {
        /* TODO: To be implemented by the student */
        Set<ResourceRecord> set = new HashSet<>();
        List<RecordType> supportedTypes = Arrays.asList(RecordType.A, RecordType.AAAA, RecordType.NS, RecordType.CNAME, RecordType.MX) ;
        if(message.getQR()) {
            verbose.printResponseHeaderInfo(message.getID(), message.getAA(), message.getRcode());
            if(message.getRcode() != 0) {
                throw new DNSErrorException("Response has error");
            }
            DNSQuestion q = message.getQuestion();
            ResourceRecord rr;
            verbose.printAnswersHeader(message.getANCount());
            for(int i = 0 ; i< message.getANCount(); i++) {
                rr = message.getRR();
                if(!supportedTypes.contains(rr.getRecordType())){
                    rr = new ResourceRecord(message.getQuestion(),(int)(rr.getRemainingTTL()), DNSMessage.byteArrayToHexString(message.getUsed()));
                }
                verbose.printIndividualResourceRecord(rr,rr.getRecordType().getCode(),rr.getRecordClass().getCode());
                cache.addResult(rr);
                set.add(rr);
            }
            verbose.printNameserversHeader(message.getNSCount());
            for(int i = 0 ; i< message.getNSCount(); i++) {
                rr = message.getRR();
                if(!supportedTypes.contains(rr.getRecordType())){
                    rr = new ResourceRecord(message.getQuestion(),(int)(rr.getRemainingTTL()), DNSMessage.byteArrayToHexString(message.getUsed()));
                }
                verbose.printIndividualResourceRecord(rr,rr.getRecordType().getCode(),rr.getRecordClass().getCode());
                cache.addResult(rr);
                set.add(rr);
            }
            verbose.printAdditionalInfoHeader(message.getARCount());
            for(int i = 0 ; i< message.getARCount(); i++) {
                rr = message.getRR();
                if(!supportedTypes.contains(rr.getRecordType())){
                    rr = new ResourceRecord(message.getQuestion(),(int)(rr.getRemainingTTL()), DNSMessage.byteArrayToHexString(message.getUsed()));
                }
                verbose.printIndividualResourceRecord(rr,rr.getRecordType().getCode(),rr.getRecordClass().getCode());
                cache.addResult(rr);
                set.add(rr);
            }
        }
        return set;
    }

    public static class DNSErrorException extends Exception {
        public DNSErrorException(String msg) {
            super(msg);
        }
    }
}