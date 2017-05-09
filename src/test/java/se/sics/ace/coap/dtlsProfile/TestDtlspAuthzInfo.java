/*******************************************************************************
 * Copyright (c) 2017, RISE SICS AB
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
package se.sics.ace.coap.dtlsProfile;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.auth.PreSharedKeyIdentity;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.coap.rs.dtlsProfile.DtlspAuthzInfo;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.TokenRepository;

/**
 * Test the DTLSProfileAuthzInfo class.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestDtlspAuthzInfo {

    static {
        ScandiumLogger.initialize();
        ScandiumLogger.setLevel(Level.FINE);
    }
    
    private static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static TokenRepository tr;
    private static CwtCryptoCtx ctx;
    private static AuthzInfo ai;
    private static DtlspAuthzInfo dai;
    private static CBORObject payload;
    
    /**
     * Set up the necessary objects.
     * 
     * @throws CoseException
     * @throws AceException
     * @throws IOException
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @BeforeClass
    public static void setUp() 
            throws CoseException, AceException, IOException, 
            IllegalStateException, InvalidCipherTextException {
        
        //Set up DTLSProfileTokenRepository
        Set<String> actions = new HashSet<>();
        actions.add("GET");
        Map<String, Set<String>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<String>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Set<String> actions2 = new HashSet<>();
        actions.add("GET");
        actions.add("POST");
        Map<String, Set<String>> myResource2 = new HashMap<>();
        myResource.put("co2", actions2);
        myScopes.put("rw_co2", myResource2);
        
        KissValidator valid = new KissValidator(Collections.singleton("rs1"),
                myScopes);
        
        TokenRepository.create(
                valid, "src/test/resources/tokens.json", null);
        tr = TokenRepository.getInstance();
        
        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());
        
        //Set up the inner Authz-Info library
        ai = new AuthzInfo(tr, Collections.singletonList("TestAS"), 
                new KissTime(), 
                null,
                valid, ctx);
        
        //Set up the DTLS authz-info resource
        dai = new DtlspAuthzInfo(ai);
        
        //Set up a token to use
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        params.put("cnf", key.AsCBOR());
        CWT token = new CWT(params);
        payload = token.encode(ctx);
        
        
    }
    
    /**
     * Test a POST to /authz-info
     * @throws UnknownHostException 
     * @throws AceException 
     */
    @Test
    public void testPOSTtoken() throws UnknownHostException, AceException {
        Request req = new Request(Code.POST);
        req.setPayload(payload.EncodeToBytes());
        req.setDestination(InetAddress.getLocalHost());
        req.setSenderIdentity(new PreSharedKeyIdentity("psk"));
        req.setType(Type.NON);
        req.setAcknowledged(false);
        req.setSource(InetAddress.getLocalHost());
        req.setSourcePort(CoAP.DEFAULT_COAP_PORT);
        req.setToken(new byte[]{0x01});
        Exchange iex = new Exchange(req, Origin.REMOTE);
        iex.setRequest(req);       
        iex.setEndpoint(new CoapEndpoint());
        CoapExchange ex = new CoapExchange(iex, dai);      
        dai.handlePOST(ex);
        
        //Test that the PoP key was stored
        Assert.assertArrayEquals(key128,
                ai.getKey("ourKey").get(KeyKeys.Octet_K).GetByteString());
        
        
       //Test that the token is there
        Assert.assertEquals(TokenRepository.OK, 
                tr.canAccess("ourKey", "ourKey", "temp", "GET", 
                        new KissTime(), null));
    }
    
    
    /**
     * Deletes the test file after the tests
     */
    @AfterClass
    public static void tearDown() {
        new File("src/test/resources/tokens.json").delete();
    }
}
