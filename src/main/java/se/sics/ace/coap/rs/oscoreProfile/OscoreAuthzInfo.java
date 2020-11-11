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
package se.sics.ace.coap.rs.oscoreProfile;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.Util;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.rs.AudienceValidator;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.IntrospectionHandler;
import se.sics.ace.rs.ScopeValidator;


/**
 * This class implements the /authz_info endpoint at the RS that receives
 * access tokens, verifies if they are valid and then stores them.
 * 
 * Note this implementation requires the following claims in a CWT:
 * iss, sub, scope, aud.
 * 
 * @author Ludwig Seitz
 *
 */
public class OscoreAuthzInfo extends AuthzInfo {
	
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(OscoreAuthzInfo.class.getName());

    /**
     * Temporary storage for the CNF claim
     */
    private CBORObject cnf;

	/**
	 * Constructor.
	 * 
	 * @param tr  a token repository
	 * @param issuers  the list of acceptable issuer of access tokens
	 * @param time  the time provider
	 * @param intro  the introspection handler (can be null)
	 * @param audience  the audience validator
	 * @param ctx  the crypto context to use with the As
	 * @param tokenFile  the file where to save tokens when persisting
     * @param scopeValidator  the application specific scope validator 
	 * @param checkCnonce  true if this RS uses cnonces for freshness validation
	 * @throws IOException 
	 * @throws AceException 
	 */
	public OscoreAuthzInfo(List<String> issuers, 
			TimeProvider time, IntrospectionHandler intro, 
			AudienceValidator audience, CwtCryptoCtx ctx, String tokenFile,
			ScopeValidator scopeValidator, boolean checkCnonce) 
			        throws AceException, IOException {
		super(issuers, time, intro, audience, ctx, tokenFile, 
		        scopeValidator, checkCnonce);
	}

	@Override
	public synchronized Message processMessage(Message msg) {
	    LOGGER.log(Level.INFO, "received message: " + msg);
	    CBORObject cbor = null;
	    
        try {
            cbor = CBORObject.DecodeFromBytes(msg.getRawPayload());
        } catch (Exception e) {
            LOGGER.info("Invalid payload at authz-info: " + e.getMessage());
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Invalid payload");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        
        if (!cbor.getType().equals(CBORType.Map)) {
            LOGGER.info("Invalid payload at authz-info: not a cbor map");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "Payload to authz-info must be a CBOR map");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        
        CBORObject nonce = cbor.get(CBORObject.FromObject(Constants.NONCE1));
        if (nonce == null || !nonce.getType().equals(CBORType.ByteString)) {
            LOGGER.info("Missing or invalid parameter type for:"
                    + "'nonce1', must be present and byte-string");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "Malformed or missing parameter 'nonce1'");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
        }
        
        CBORObject senderIdCBOR = cbor.get(CBORObject.FromObject(Constants.ID1));
        if (senderIdCBOR == null || !senderIdCBOR.getType().equals(CBORType.ByteString)) {
            LOGGER.info("Missing or invalid parameter type for:"
                    + "'id1', must be present and byte-string");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "Malformed or missing parameter 'id1'");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
        }
        
        CBORObject token = cbor.get(
                CBORObject.FromObject(Constants.ACCESS_TOKEN));
        if (token == null) {
            LOGGER.info("Missing mandatory parameter 'access_token'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "Missing mandatory parameter 'access_token'");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        
        Message reply = super.processToken(token, msg);
        if (reply.getMessageCode() != Message.CREATED) {
            return reply;
        }
        
        if (this.cnf == null) {//Should never happen, caught in TokenRepository
            LOGGER.info("Missing required parameter 'cnf'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
        }
        
        CBORObject authzInfoResponse = CBORObject.DecodeFromBytes(reply.getRawPayload());
        
        String recipientIdString = authzInfoResponse.get(
                CBORObject.FromObject(Constants.CLIENT_ID)).AsString();
        if (recipientIdString == null) {
            LOGGER.info("Missing mandatory parameter 'client_id'");
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        byte[] recipientId = Base64.getDecoder().decode(recipientIdString);
        
        
        byte[] n1 = nonce.GetByteString();
        byte[] n2 = new byte[8];
        new SecureRandom().nextBytes(n2);
   
        OscoreSecurityContext osc;
        try {
            osc = new OscoreSecurityContext(this.cnf);
            
        } catch (AceException e) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
        }
            
        OSCoreCtx ctx;
        try {
        	byte[] senderId = senderIdCBOR.GetByteString();        	
            ctx = osc.getContext(false, n1, n2, senderId, recipientId);
            OscoreCtxDbSingleton.getInstance().addContext(ctx);
        } catch (OSException e) {
            LOGGER.info("Error while creating OSCORE context: " 
                    + e.getMessage());
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "Error while creating OSCORE security context: "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.NONCE2, n2);
        
        payload.Add(Constants.ID2, recipientId);
        
        LOGGER.info("Successfully processed OSCORE token");
        return msg.successReply(reply.getMessageCode(), payload);
	}

	@Override
	protected synchronized void processOther(Map<Short, CBORObject> claims) {
	    this.cnf = claims.get(Constants.CNF);
	}

    @Override
    public void close() throws AceException {
       super.close();
        
    }	
}
