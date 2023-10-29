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
package se.sics.ace.oscore.rs.oscoreGroupManager;

import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.KeyKeys;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommErrors;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.Util;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.rs.TokenRepository;

/**
 * Definition of the Group OSCORE group-membership sub-resource /kdc-cred
 */
public class GroupOSCORESubResourceKdcCred extends CoapResource {
	
	private Map<String, GroupInfo> existingGroupInfo = new HashMap<>();
	
	/**
     * Constructor
     * @param resId  the resource identifier
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     */
    public GroupOSCORESubResourceKdcCred(String resId, Map<String, GroupInfo> existingGroupInfo) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"kdc-cred\" " + resId);
        
        this.existingGroupInfo = existingGroupInfo;
        
    }

    @Override
    public void handleGET(CoapExchange exchange) {
    	System.out.println("GET request reached the GM");
    	
    	// Retrieve the entry for the target group, using the last path segment of
    	// the URI path as the name of the OSCORE group
    	GroupInfo targetedGroup = existingGroupInfo.get(this.getParent().getName());
    	
    	// This should never happen if existing groups are maintained properly
    	if (targetedGroup == null) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
        	return;
    	}
    	
    	String groupName = targetedGroup.getGroupName();
    	
    	// This should never happen if active groups are maintained properly
	  		if (!groupName.equals(this.getParent().getName())) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
				return;
			}
    	
    	String subject = null;
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen,
        	// due to the earlier check at the Token Repository
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED,
        					 "Unauthenticated client tried to get access");
        	return;
        }
    	
    	if (!targetedGroup.isGroupMember(subject)) {
    		
    		// The requester is not a current group member.
    		//
    		// This is still fine, as long as at least one Access Tokens
    		// of the requester allows also the role "Verifier" in this group
    		
    		// Check that at least one of the Access Tokens for this node
    		// allows (also) the Verifier role for this group
        	
    		int role = 1 << GroupcommParameters.GROUP_OSCORE_VERIFIER;
    		boolean allowed = false;
        	int[] roleSetToken = Util.getGroupOSCORERolesFromToken(subject, groupName);
        	if (roleSetToken == null) {
        		exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
        						 "Error when retrieving allowed roles from Access Tokens");
        		return;
        	}
        	else {
        		for (int index = 0; index < roleSetToken.length; index++) {
        			if ((role & roleSetToken[index]) != 0) {
            			// 'scope' in this Access Token admits (also) the role "Verifier" for this group.
        				// This makes it fine for the requester.
        				allowed = true;
        				break;
        			}
        		}
        	}
        	
        	if (!allowed) {
        		// The requester is a group member or is not a signature verifier
        		CBORObject responseMap = CBORObject.NewMap();
        		responseMap.Add(GroupcommParameters.ERROR, GroupcommErrors.ONLY_FOR_SIGNATURE_VERIFIERS);
        		byte[] responsePayload = responseMap.EncodeToBytes();
        		exchange.respond(CoAP.ResponseCode.FORBIDDEN,
        						 responsePayload,
        						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        		return;
        	}
        	
    	}
    	
    	if (targetedGroup.getMode() == GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
    		// The group uses only the pairwise mode
    		CBORObject responseMap = CBORObject.NewMap();
    		responseMap.Add(GroupcommParameters.ERROR, GroupcommErrors.SIGNATURES_NOT_USED);
    		byte[] responsePayload = responseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 responsePayload,
    						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
    	}
        
    	// Respond to the KDC Authentication Credential Request
        
    	CBORObject myResponse = CBORObject.NewMap();
		
		// Authentication Credential of the Group Manager together with proof-of-possession evidence
    	byte[] kdcNonce = new byte[8];
    	new SecureRandom().nextBytes(kdcNonce);
    	myResponse.Add(GroupcommParameters.KDC_NONCE, kdcNonce);
    	
    	CBORObject authCred = CBORObject.FromObject(targetedGroup.getGmAuthCred());
    	
    	myResponse.Add(GroupcommParameters.KDC_CRED, authCred);
    	
    	PrivateKey gmPrivKey;
		try {
			gmPrivKey = targetedGroup.getGmKeyPair().AsPrivateKey();
		} catch (CoseException e) {
			System.err.println("Error when computing the GM PoP evidence " + e.getMessage());
			exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
							 "Error when computing the GM PoP evidence");
    		return;
		}
		int signKeyCurve = 0;
		if (targetedGroup.getGmKeyPair().get(KeyKeys.KeyType).AsInt32() == KeyKeys.KeyType_EC2.AsInt32()) {
			signKeyCurve = targetedGroup.getGmKeyPair().get(KeyKeys.EC2_Curve).AsInt32();
		}
		if (targetedGroup.getGmKeyPair().get(KeyKeys.KeyType).AsInt32() == KeyKeys.KeyType_OKP.AsInt32()) {
			signKeyCurve = targetedGroup.getGmKeyPair().get(KeyKeys.OKP_Curve).AsInt32();
		}
		
		
		String cNonceString = TokenRepository.getInstance().getCnonce(subject);
		if(cNonceString == null) {
		    // Return an error response
			System.err.println("Error when retrieving the nonce to use as N_C");
			exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
							 "Error when retrieving the nonce to use as N_C");
		    return;
		}
		byte[] cnonce = Base64.getDecoder().decode(cNonceString);
		
		// TODO: Per the forthcoming draft-ietf-ace-key-groupcomm-oscore-17, build a
		// PoP input composed of (N_C | kdcNonce), each wrapped in a CBOR byte string
		
		
    	byte[] gmSignature = Util.computeSignature(signKeyCurve, gmPrivKey, kdcNonce);

    	if (gmSignature != null) {
    		myResponse.Add(GroupcommParameters.KDC_CRED_VERIFY, gmSignature);
    	}
    	else {
			exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
							 "Error when computing the GM PoP evidence");
    		return;
    	}

    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);

    }

}
