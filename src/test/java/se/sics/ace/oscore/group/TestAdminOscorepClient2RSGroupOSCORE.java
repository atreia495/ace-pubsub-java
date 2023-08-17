/*******************************************************************************
 * Copyright (c) 2019, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.ace.oscore.group;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.MessageTag;

import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.GroupcommPolicies;
import se.sics.ace.Util;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.OSCOREProfileRequestsGroupOSCORE;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * A test case for the OSCORE profile interactions between
 * a Group OSCORE Administrator acting as ACE Client and
 * an OSCORE Group Manager acting as ACE Resource Server.
 * 
 * @author Marco Tiloca
 *
 */
public class TestAdminOscorepClient2RSGroupOSCORE {
	
	private final String groupCollectionResourcePath = "admin";

	// Sets the port of the RS
	private final static int PORT = 5685;
	
    private final static int MAX_UNFRAGMENTED_SIZE = 4096;
    
    /**
     * The cnf key used in these tests, when the ACE Client is the group Administrator 
     */
    private static byte[] keyCnfAdmin = {'a', 'b', 'c', 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    
    /**
     * The cnf key used in these tests, when the ACE Client is a group member
     */
    private static byte[] keyCnfGroupMember = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    /**
     * The AS <-> RS key used in these tests
     */
    private static byte[] keyASRS = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static RunTestServer srv = null;
    private static OSCoreCtx osctx;
    
    private static OSCoreCtxDB ctxDB;
    
	// Each set of the list refers to a different size of Recipient IDs.
	// The element with index 0 includes as elements Recipient IDs with size 1 byte.
	private static List<Set<Integer>> usedRecipientIds = new ArrayList<Set<Integer>>();
    
    private static class RunTestServer implements Runnable {
        
        public RunTestServer() {
           //Do nothing
        }

        /**
         * Stop the server
         * @throws Exception 
         */
        public void stop() throws Exception {
            TestAdminOscorepRSGroupOSCORE.stop();
        }
        
        @Override
        public void run() {
            try {
            	TestAdminOscorepRSGroupOSCORE.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                try {
                	TestAdminOscorepRSGroupOSCORE.stop();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        
    }
    
    /**
     * This sets up everything for the tests including the server
     * @throws OSException 
     */
    @BeforeClass
    public static void setUp() throws OSException {    	
        srv = new RunTestServer();
        srv.run();
        
        //Initialize a fake context
        osctx = new OSCoreCtx(keyCnfAdmin, true, null, 
                "clientA".getBytes(Constants.charset),
                "rs1".getBytes(Constants.charset),
                null, null, null, null, MAX_UNFRAGMENTED_SIZE);
    	
        ctxDB = new org.eclipse.californium.oscore.HashMapCtxDB();
        
    	for (int i = 0; i < 4; i++) {
        	// Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		usedRecipientIds.add(new HashSet<Integer>());
    		
    	}
    }
    
    /**
     * Deletes the test DB after the tests
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        srv.stop();
    }
    
    /**
     * Test successful submission of a token to the RS with subsequent
     * access based on the token
     * 
     * @throws Exception 
     */
    @Test
    public void testSuccess() throws Exception {

        //Generate a token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx  = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_helloWorld"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, keyCnfAdmin);
        osc.Add(Constants.OS_ID, Util.intToBytes(3));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        Response rsRes = OSCOREProfileRequests.postToken(
                "coap://localhost:" + PORT + "/authz-info", asRes, ctxDB, usedRecipientIds);
        
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(ctxDB.getContext("coap://localhost:" + PORT + "/helloWorld"));
       
       //Submit a request

       CoapClient c = OSCOREProfileRequestsGroupOSCORE.getClient(new InetSocketAddress(
               "coap://localhost:" + PORT + "/helloWorld", PORT), ctxDB);
       
       Request helloReq = new Request(CoAP.Code.GET);
       helloReq.getOptions().setOscore(new byte[0]);
       CoapResponse helloRes = c.advanced(helloReq);
       Assert.assertEquals("Hello World!", helloRes.getResponseText());
       
       //Submit a forbidden request
       
       CoapClient c2 = OSCOREProfileRequestsGroupOSCORE.getClient(new InetSocketAddress(
    		   "coap://localhost:" + PORT + "/temp", PORT), ctxDB);
       
       Request getTemp = new Request(CoAP.Code.GET);
       getTemp.getOptions().setOscore(new byte[0]);
       CoapResponse getTempRes = c2.advanced(getTemp);
       assert(getTempRes.getCode().equals(CoAP.ResponseCode.FORBIDDEN));
       
       //Submit a request with unallowed method
       Request deleteHello = new Request(CoAP.Code.DELETE);
       deleteHello.getOptions().setOscore(new byte[0]);
       CoapResponse deleteHelloRes = c.advanced(deleteHello);
       assert(deleteHelloRes.getCode().equals(CoAP.ResponseCode.METHOD_NOT_ALLOWED));
       
    }
    

    /**
     * Test admin operations at the OSCORE Group Manager
     * Uses the ACE OSCORE Profile.
     * 
     * @throws Exception 
     */
    @Test
    public void testAdminOperations() throws Exception {
        
        //Generate a token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        Map<Short, CBORObject> params = new HashMap<>(); 
        
        //Create the scope        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        
        String groupNamePattern = new String("gp1");
        cborArrayEntry.Add(groupNamePattern);
        
    	int myPermissions = 0;
    	myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_LIST);
    	myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_CREATE);
    	myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_READ);
    	myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_WRITE);
    	myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_DELETE);
    	cborArrayEntry.Add(myPermissions);
    	
        
        cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token4JoinSingleRole".getBytes(Constants.charset))); //Need different CTI
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, keyCnfAdmin);
        osc.Add(Constants.OS_ID, Util.intToBytes(4));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        Response rsRes = OSCOREProfileRequests.postToken(
        		"coap://localhost:" + PORT + "/authz-info", asRes, ctxDB, usedRecipientIds);
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(ctxDB.getContext("coap://localhost:" + PORT + "/helloWorld"));

        
        CoapClient c = null;
        Request adminReq = null;
        CoapResponse adminRes = null;
        CBORObject requestPayloadCbor = null;
        CBORObject responsePayloadCbor = null;
        
        // ============================================
        
        // Send a GET request to /admin
        
        System.out.println();
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath, PORT),
        		ctxDB);
        
        adminReq = new Request(CoAP.Code.GET);
        adminReq.getOptions().setOscore(new byte[0]);
        
        adminRes = c.advanced(adminReq);
        
        System.out.println(new String(adminRes.getPayload()));
        // Assert.assertEquals(0, adminRes.getPayloadSize());
        
        // ============================================
        
        // Send a FETCH request to /admin
        
        System.out.println();
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath, PORT),
        		ctxDB);
        
        adminReq = new Request(CoAP.Code.FETCH);
        adminReq.getOptions().setOscore(new byte[0]);
        adminReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        requestPayloadCbor = CBORObject.NewMap();
        requestPayloadCbor.Add(GroupcommParameters.GROUP_NAME, "gp1");
        adminReq.setPayload(requestPayloadCbor.EncodeToBytes());
        
        adminRes = c.advanced(adminReq);
        
        System.out.println(new String(adminRes.getPayload()));
        // Assert.assertEquals(0, adminRes.getPayloadSize());
        
        // ============================================
        
        // Send a POST request to /admin

        System.out.println();
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath, PORT),
        		ctxDB);
        
        adminReq = new Request(CoAP.Code.POST);
        adminReq.getOptions().setOscore(new byte[0]);
        adminReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        requestPayloadCbor = CBORObject.NewMap();
        requestPayloadCbor.Add(GroupcommParameters.GROUP_NAME, CBORObject.FromObject("gp1"));
        adminReq.setPayload(requestPayloadCbor.EncodeToBytes());
        
        adminRes = c.advanced(adminReq);
        Assert.assertNotNull(adminRes);
        Assert.assertNotNull(adminRes.getPayload());
        
        responsePayloadCbor = CBORObject.DecodeFromBytes(adminRes.getPayload());
        Assert.assertNotNull(responsePayloadCbor);
        
        Assert.assertEquals(CBORType.Map, responsePayloadCbor.getType());
        System.out.println(responsePayloadCbor.toString());
        // Assert.assertEquals(0, responsePayloadCbor.size());

    }
    
    /**
     * Test unauthorized access to the RS
     * 
     * @throws Exception 
     */
    @Test
    public void testNoAccess() throws Exception {
        
        ctxDB.addContext("coap://localhost:" + PORT + "/helloWorld", osctx);
        CoapClient c = OSCOREProfileRequests.getClient(
                new InetSocketAddress("coap://localhost:" + PORT + "/helloWorld", PORT), ctxDB);
        
        CoapResponse res = c.get();
        assert(res.getCode().equals(CoAP.ResponseCode.UNAUTHORIZED));
    }
   
}
