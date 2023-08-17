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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommErrors;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.GroupcommPolicies;
import se.sics.ace.Util;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.OSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.rs.GroupOSCOREValidator;
import se.sics.ace.rs.TokenRepository;

/**
 * Definition of the Group OSCORE group-collection resource
 */
public class GroupOSCOREGroupConfigurationResource extends CoapResource {
	
	private Map<String, GroupInfo> existingGroupInfo = new HashMap<>();
	
	private final String groupAdminResourcePath = "admin";
	
	private Map<String, Map<String, Set<Short>>> myScopes;
	
	private GroupOSCOREValidator valid;

	private CBORObject groupConfiguration = CBORObject.NewMap();
	
	/**
     * Constructor
     * @param resId  the resource identifier
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     * @param myScopes  the scopes of this OSCORE Group Manager
     * @param valid  the access validator of this OSCORE Group Manager
     */
    public GroupOSCOREGroupConfigurationResource(String resId,
			  									 Map<String, GroupInfo> existingGroupInfo,
    										     Map<String, Map<String, Set<Short>>> myScopes,
    										     GroupOSCOREValidator valid) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group Configuration Resource " + resId);
     
        this.existingGroupInfo = existingGroupInfo;
        this.myScopes = myScopes;
        this.valid = valid;
    }

    @Override
    public synchronized void handleGET(CoapExchange exchange) {
    	System.out.println("GET request reached the GM");
        
    	// Process the request for retrieving the Group Configuration
    	
    	String subject = null;
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED,
        					 "Unauthenticated client tried to get access");
        	return;
        }
    	
    	// Respond to the request for retrieving the Group Configuration
        
    	CBORObject myResponse = CBORObject.NewMap();
    	for (CBORObject elemKey : this.groupConfiguration.getKeys()) {
    		myResponse.Add(this.groupConfiguration.get(elemKey));
    	}
    	
    	// Fill in the response

    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);

    }
    
    @Override
    public synchronized void handleFETCH(CoapExchange exchange) {
    	System.out.println("FETCH request reached the GM");
        
    	// Process the request for retrieving part of a Group Configuration by filters
    	
    	String subject = null;
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED,
        					 "Unauthenticated client tried to get access");
        	return;
        }
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
		
    	// The payload of the request must be a CBOR Map
    	if (!requestCBOR.getType().equals(CBORType.Map)) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}
    	
    	// The CBOR Map in the payload must have only one element
    	if (requestCBOR.size() != 1) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}
    	
    	// The element of the CBOR Map must be 'conf_filter'
    	if (requestCBOR.ContainsKey(GroupcommParameters.CONF_FILTER) == false) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}
    	
    	// The 'conf_filter' element of the CBOR Map must be a CBOR array
    	if (requestCBOR.get(GroupcommParameters.CONF_FILTER).getType() != CBORType.Array) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}
    	
    	
    	// Respond to the request for retrieving part of a Group Configuration by filters
        
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	// Fill in the response

    	for (int i = 0; i < requestCBOR.size(); i++) {
    		CBORObject elemKey = requestCBOR.get(i);
    		if (this.groupConfiguration.ContainsKey(elemKey)) {
    				myResponse.Add(elemKey, this.groupConfiguration.get(elemKey));
    		}
    	}
    	
    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);

    }
    
    @Override
    public synchronized void handlePUT(CoapExchange exchange) {
        
    	System.out.println("PUT request reached the GM");
    	
    	// Process the request for overwriting a Group Configuration
    	
    	String subject = null;
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED,
        					 "Unauthenticated client tried to get access");
        	return;
        }
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
    	
    	// TODO
    	
    	
    	// Respond to the request for overwriting a Group Configuration
        
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	// Fill in the response

    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);
    	
    }
    
    @Override
    public synchronized void handlePATCH(CoapExchange exchange) {
        
    	System.out.println("PATCH request reached the GM");
    	
    	// Process the request for selectively updating a Group Configuration
    	
    	String subject = null;
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED,
        					 "Unauthenticated client tried to get access");
        	return;
        }
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
    	
    	// TODO
    	
    	
    	// Respond to the request for selectively updating a Group Configuration
        
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	// Fill in the response

    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);
    	
    }
    
    @Override
    public synchronized void handleIPATCH(CoapExchange exchange) {
        
    	System.out.println("iPATCH request reached the GM");
    	
    	// Process the request for selectively updating a Group Configuration
    	
    	String subject = null;
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED,
        					 "Unauthenticated client tried to get access");
        	return;
        }
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
    	
    	// TODO
    	
    	
    	// Respond to the request for selectively updating a Group Configuration
        
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	// Fill in the response

    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);
    	
    }
    
    @Override
    public synchronized void handleDELETE(CoapExchange exchange) {
        
    	System.out.println("DELETE request reached the GM");
    	
    	// Process the request for deleting a Group Configuration
    	
    	String subject = null;
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED,
        					 "Unauthenticated client tried to get access");
        	return;
        }
    	
    	// Respond to the request for deleting a Group Configuration
        
    	Response coapResponse = new Response(CoAP.ResponseCode.DELETED);

    	delete();
    	exchange.respond(coapResponse);
    	
    }
    
	/**
     * Return the group configuration as a CBOR map
     * 
     * @return  the group configuration
     */
    public CBORObject getConfigurationParameters() {
    	return this.groupConfiguration;
    }

	/**
     * Return the default value for a certain parameter
     * 
     * @param paramAbbreviation  the parameter for which to retrieve the default value
     * @return  the default value, or null in case of invalid parameter
     */
    public static CBORObject getDefaultValue(short paramAbbreviation) {
    	
    	if (paramAbbreviation == GroupcommParameters.HKDF.AsInt32()) {
    		return CBORObject.FromObject(AlgorithmID.HMAC_SHA_256); // HMAC 256/256 for HKDF SHA-256
    	}
    	if (paramAbbreviation == GroupcommParameters.CRED_FMT.AsInt32()) {
    		return CBORObject.FromObject(Constants.COSE_HEADER_PARAM_CCS); // CWT Claims Set (CCS)
    	}
    	if (paramAbbreviation == GroupcommParameters.GROUP_MODE.AsInt32()) {
			return CBORObject.True;
    	}
    	if (paramAbbreviation == GroupcommParameters.GP_ENC_ALG.AsInt32()) {
    		return CBORObject.FromObject(AlgorithmID.AES_CCM_16_64_128); // AES-CCM-16-64-128
    	}
    	if (paramAbbreviation == GroupcommParameters.SIGN_ALG.AsInt32()) {
    		return CBORObject.FromObject(AlgorithmID.EDDSA); // EdDSA
    	}    	
    	if (paramAbbreviation == GroupcommParameters.PAIRWISE_MODE.AsInt32()) {
			return CBORObject.True;
    	}
    	if (paramAbbreviation == GroupcommParameters.ALG.AsInt32()) {
    		return CBORObject.FromObject(AlgorithmID.AES_CCM_16_64_128); // AES-CCM-16-64-128
    	}
    	if (paramAbbreviation == GroupcommParameters.ECDH_ALG.AsInt32()) {
			return CBORObject.FromObject(AlgorithmID.ECDH_SS_HKDF_256); // ECDH-SS + HKDF-256
    	}
    	if (paramAbbreviation == GroupcommParameters.DET_REQ.AsInt32()) {
			return CBORObject.False;
    	}
    	if (paramAbbreviation == GroupcommParameters.DET_HASH_ALG.AsInt32()) {
			return CBORObject.FromObject(AlgorithmID.HMAC_SHA_256);
    	}
    	if (paramAbbreviation == GroupcommParameters.ACTIVE.AsInt32()) {
    		return CBORObject.False;
    	}
    	if (paramAbbreviation == GroupcommParameters.GROUP_TITLE.AsInt32()) {
    		return CBORObject.Null;
    	}
    	if (paramAbbreviation == GroupcommParameters.MAX_STALE_SETS.AsInt32()) {
    		return CBORObject.FromObject(3);
    	}
    	if (paramAbbreviation == GroupcommParameters.GID_REUSE.AsInt32()) {
    		return CBORObject.False;
    	}
    	if (paramAbbreviation == GroupcommParameters.APP_GROUPS.AsInt32()) {
    		return CBORObject.NewArray();
    	}
    	if (paramAbbreviation == GroupcommParameters.GROUP_POLICIES.AsInt32()) {
			CBORObject ret = CBORObject.NewMap();
			ret.Add(GroupcommPolicies.KEY_CHECK_INTERVAL, 3600);
			ret.Add(GroupcommPolicies.EXP_DELTA, 0);
			return ret;
    	}
    	
    	return null;
    	
    }
    
    public static CBORObject getDefaultValueSignParams(CBORObject signAlg) {
    	CBORObject ret = null;
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.EDDSA))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_OKP);
        	ret.get(1).Add(KeyKeys.KeyType_OKP);
        	ret.get(1).Add(KeyKeys.OKP_Ed25519);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.ECDSA_256))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.EC2_P256);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.ECDSA_384))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.EC2_P384);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.ECDSA_512))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.EC2_P521);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.RSA_PSS_256)) ||
    		signAlg.equals(CBORObject.FromObject(AlgorithmID.RSA_PSS_384)) ||
    		signAlg.equals(CBORObject.FromObject(AlgorithmID.RSA_PSS_512))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_RSA);
        	ret.get(1).Add(KeyKeys.KeyType_RSA);
    		return ret;
    	}
    	return ret;
    }
    
    public static CBORObject getDefaultValueEcdhParams(CBORObject signAlg, boolean groupMode) {
    	CBORObject ret = null;
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.EDDSA)) || (groupMode == false)) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_OKP);
        	ret.get(1).Add(KeyKeys.KeyType_OKP);
        	ret.get(1).Add(KeyKeys.OKP_X25519);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.ECDSA_256))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.EC2_P256);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.ECDSA_384))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.EC2_P384);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.ECDSA_512))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.EC2_P521);
    		return ret;
    	}
    	return ret;
    }
    
}
