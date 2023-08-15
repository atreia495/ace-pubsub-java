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
public class GroupOSCOREGroupCollectionResource extends CoapResource {
	
	private Map<String, GroupOSCOREGroupConfigurationResource> groupConfigurationResources = new HashMap<>();
	
	private Map<String, GroupInfo> existingGroupInfo = new HashMap<>();
	
    private final static String rootGroupMembershipResourcePath = "ace-group";
	
	private Map<String, Map<String, Set<Short>>> myScopes;
	
	private GroupOSCOREValidator valid;
	
	/**
     * Constructor
     * @param resId  the resource identifier
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     * @param myScopes  the scopes of this OSCORE Group Manager
     * @param valid  the access validator of this OSCORE Group Manager
     */
    public GroupOSCOREGroupCollectionResource(String resId,
    										  Map<String, GroupInfo> existingGroupInfo,
    										  Map<String, Map<String, Set<Short>>> myScopes,
    										  GroupOSCOREValidator valid) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group Collection Resource " + resId);
     
        this.existingGroupInfo = existingGroupInfo;
        this.myScopes = myScopes;
        this.valid = valid;
        
        // TODO: remove
        // ============
        // Force the presence of an already existing group configuration for early testing
        GroupOSCOREGroupConfigurationResource testConf = new GroupOSCOREGroupConfigurationResource(
        													"gp1", this.existingGroupInfo,
        													this.myScopes, this.valid);
        testConf.getConfigurationParameters().Add(GroupcommParameters.GROUP_NAME, CBORObject.FromObject("gp1"));
        this.groupConfigurationResources.put("gp1", testConf);
        // ============
        
    }

    @Override
    public synchronized void handleGET(CoapExchange exchange) {
    	System.out.println("GET request reached the GM");
        
    	// Process the request for retrieving the full list of Group Configurations
    	
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
        
    	// Check that at least one scope entry in the access token allows the "List" admin permission
    	CBORObject[] permissionSetToken = Util.getGroupOSCOREAdminPermissionsFromToken(subject, null);
    	if (permissionSetToken == null) {
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN,
    						 "Operation not permitted");
    		return;
    	}        
    	
    	
    	String auxString = new String("");
    	
    	for (String groupName : this.groupConfigurationResources.keySet()) {
    		boolean selected = false;
    		
    		for (int i = 0; i < permissionSetToken.length; i++) {
    			if (Util.matchingGroupOscoreName(groupName, permissionSetToken[i].get(0))) {
    				try {
        				int permissions = permissionSetToken[i].get(1).AsInt32();
    					if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_LIST)) {
    						// One match has been found
    						selected = true;
    						break;
    					}
					} catch (AceException e) {
						System.err.println("Error while checking the group name against the group name pattern: " + e.getMessage());
					}
    			}
    		}
    		
    		if (selected == false) {
    			// Move to the next group-configuration resource
    			continue;
    		}
    		
    		// This group configuration has passed the filtering and has been selected
    		if (auxString.equals("") == false) {
    			auxString += ",";
    		}
    		auxString += "<" + this.getURI() + "/" + groupName + ">;rt=\"core.osc.gconf\"";
    	}
    	
    	// Respond to the request for retrieving the full list of Group Configurations

    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);

    	if (this.existingGroupInfo.size() != 0) {
        	byte[] responsePayload = auxString.getBytes(Constants.charset);
        	coapResponse.setPayload(responsePayload);
    		coapResponse.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_LINK_FORMAT);
    	}

    	exchange.respond(coapResponse);

    }
    
    @Override
    public synchronized void handleFETCH(CoapExchange exchange) {
    	System.out.println("FETCH request reached the GM");
        
    	// Process the request for retrieving a list of Group Configurations by filters
    	
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
    	
    	// Check that at least one scope entry in the access token allows the "List" admin permission
    	CBORObject[] permissionSetToken = Util.getGroupOSCOREAdminPermissionsFromToken(subject, null);
    	if (permissionSetToken == null) {
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN,
    						 "Operation not permitted");
    		return;
    	}
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null || (requestPayload.length == 0)) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}
    	
    	if(exchange.getRequestOptions().hasContentFormat() == false ||
    	   exchange.getRequestOptions().getContentFormat() != Constants.APPLICATION_ACE_GROUPCOMM_CBOR) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "The CoAP option Content-Format must be present, with value application/ace-groupcomm+cbor");
    		return;
    	}

    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
    	
    	// The payload of the request must be a CBOR Map
    	if (!requestCBOR.getType().equals(CBORType.Map)) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}
    	
    	String auxString = new String("");
    	
    	for (String groupName : this.groupConfigurationResources.keySet()) {
    		
			boolean selected = false;
    		
		    for (int i = 0; i < permissionSetToken.length; i++) {
		        if (Util.matchingGroupOscoreName(groupName, permissionSetToken[i].get(0))) {
		            try {
			            int permissions = permissionSetToken[i].get(1).AsInt32();
		                if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_LIST)) {
		                    // One match has been found
		                    selected = true;
		                    break;
		                }
		            } catch (AceException e) {
		                System.err.println("Error while checking the group name against the group name pattern: " + e.getMessage());
		            }
		        }
		    }
		    
		    if (selected == false) {
		        // Move to the next group-configuration resource
		        continue;
		    }
		    
			CBORObject configurationParameters = this.groupConfigurationResources.get(groupName).getConfigurationParameters();
		    
    		// Perform the filtering based on the specified filter criteria
    		for (CBORObject elemKey : requestCBOR.getKeys()) {
    			
    			// The parameter in the filter must be present in the configuration
    			if (configurationParameters.ContainsKey(elemKey) == false) {
    				selected = false;
    				break;
    			}
    			
    			if (requestCBOR.get(elemKey).equals(configurationParameters.get(elemKey)) == false) {
					selected = false;
					break;
    			}
    			
    		}
    		
			if (selected == true) {
    			// This group configuration has passed the filtering and has been selected
	    		if (auxString.equals("") == false) {
	    			auxString += ",";
	    		}
        		auxString += "<" + this.getURI() + "/" + groupName + ">;rt=\"core.osc.gconf\"";
			}

    	}
    	
    	
    	// Respond to the request for retrieving a list of Group Configurations by filters
        
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);

    	if (this.existingGroupInfo.size() != 0) {
        	byte[] responsePayload = auxString.getBytes(Constants.charset);
        	coapResponse.setPayload(responsePayload);
    		coapResponse.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_LINK_FORMAT);
    	}

    	exchange.respond(coapResponse);

    }
    
    @Override
    public synchronized void handlePOST(CoapExchange exchange) {
        
    	System.out.println("POST request reached the GM");
    	
    	// Process the request for creating a new Group Configuration
    	
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
    	
    	if(requestPayload == null || (requestPayload.length == 0)) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}
    	
    	if(exchange.getRequestOptions().hasContentFormat() == false ||
    	   exchange.getRequestOptions().getContentFormat() != Constants.APPLICATION_ACE_GROUPCOMM_CBOR) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "The CoAP option Content-Format must be present, with value application/ace-groupcomm+cbor");
    		return;
    	}

    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
    	
    	// The payload of the request must be a CBOR Map
    	if (!requestCBOR.getType().equals(CBORType.Map)) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}
    	
    	// TODO
    	
    	
    	// Respond to the request for creating a new Group Configuration
        
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	// Fill in the response

    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);
    	
    }
}
