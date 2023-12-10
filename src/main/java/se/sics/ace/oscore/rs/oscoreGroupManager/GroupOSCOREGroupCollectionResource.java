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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.util.Bytes;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.OneKey;
import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommErrors;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.Util;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.rs.GroupOSCOREValidator;

/**
 * Definition of the Group OSCORE group-collection resource
 */
public class GroupOSCOREGroupCollectionResource extends CoapResource {
	
	private Map<String, GroupOSCOREGroupConfigurationResource> groupConfigurationResources = new HashMap<>();
	
	Resource groupOSCORERootGroupMembership;
	
	private int groupIdPrefixSize;
	
	private Set<CBORObject> usedGroupIdPrefixes = new HashSet<>();
	
	private String prefixMonitorNames;
	
	private String nodeNameSeparator;
	
	private int maxStaleIdsSets;
	
	private Map<String, GroupInfo> existingGroupInfo = new HashMap<>();
	
	private Map<String, Map<String, Set<Short>>> myScopes;
	
	private GroupOSCOREValidator valid;

    // The map key is the cryptographic curve; the map key is the hex string of the key pair
    private Map<CBORObject, String> gmSigningKeyPairs;
    
    // For the outer map, the map key is the type of authentication credential
    // For the inner map, the map key is the cryptographic curve, while the map value is the hex string of the authentication credential
    private Map<Integer,  Map<CBORObject, String>> gmSigningPublicAuthCred;
    
    // The map key is the cryptographic curve; the map key is the hex string of the key pair
    private Map<CBORObject, String> gmKeyAgreementKeyPairs;
    
    // For the outer map, the map key is the type of authentication credential
    // For the inner map, the map key is the cryptographic curve, while the map value is the hex string of the authentication credential
    private Map<Integer,  Map<CBORObject, String>> gmKeyAgreementPublicAuthCred;
    
	private final String asUri = new String("coap://as.example.com/token");
	
    private final static String rootGroupMembershipResourcePath = "ace-group";
    
    private final static String groupCollectionResourcePath = "admin";
		
	/**
     * Constructor
     * @param resId  the resource identifier
     * @param groupOSCORERootGroupMembership  the root group-membership resource
     * @param groupIdPrefixSize  the size in bytes of the Group ID prefixes
     * @param usedGroupIdPrefixes  the set of currently used Group ID prefixes
     * @param prefixMonitorNames  initial part of the node name for monitors
     * @param nodeNameSeparator  for non-monitor members, separator between the two components of the node name
     * @param maxStaleIdsSets  the maximum number of sets of stale Sender IDs for the group 
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     * @param gmSigningKeyPairs  the signing key pairs of the Group Manager
     * @param gmSigningPublicAuthCred  the signing public authentication credentials of the Group Manager
     * @param gmKeyAgreementKeyPairs  the key agreement key pairs of the Group Manager
     * @param gmKeyAgreementPublicAuthCred  the key agreement public authentication credentials of the Group Manager
     * @param myScopes  the scopes of this OSCORE Group Manager
     * @param valid  the access validator of this OSCORE Group Manager
     */
    public GroupOSCOREGroupCollectionResource(String resId,
    										  Resource groupOSCORERootGroupMembership,
    										  final int groupIdPrefixSize,
    										  Set<CBORObject> usedGroupIdPrefixes,
    										  String prefixMonitorNames,
    										  String nodeNameSeparator,
    										  int maxStaleIdsSets,
    										  Map<String, GroupInfo> existingGroupInfo,
    										  Map<CBORObject, String> gmSigningKeyPairs,
    										  Map<Integer,  Map<CBORObject, String>> gmSigningPublicAuthCred,
    										  Map<CBORObject, String> gmKeyAgreementKeyPairs,
    										  Map<Integer,  Map<CBORObject, String>> gmKeyAgreementPublicAuthCred,
    										  Map<String, Map<String, Set<Short>>> myScopes,
    										  GroupOSCOREValidator valid) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group Collection Resource " + resId);
     
        this.groupOSCORERootGroupMembership = groupOSCORERootGroupMembership;
        
        this.groupIdPrefixSize = groupIdPrefixSize;
        this.usedGroupIdPrefixes = usedGroupIdPrefixes;
        
        this.prefixMonitorNames = prefixMonitorNames;
        this.nodeNameSeparator = nodeNameSeparator;
        this.maxStaleIdsSets = maxStaleIdsSets;
        
        
        this.existingGroupInfo = existingGroupInfo;
        
        this.gmSigningKeyPairs = gmSigningKeyPairs;
        this.gmSigningPublicAuthCred = gmSigningPublicAuthCred;
        this.gmKeyAgreementKeyPairs = gmKeyAgreementKeyPairs;
        this.gmKeyAgreementPublicAuthCred = gmKeyAgreementPublicAuthCred;
        
        this.myScopes = myScopes;
        this.valid = valid;
        
        // TODO: remove
        // ============
        // Force the presence of an already existing group configuration for early testing
        GroupOSCOREGroupConfigurationResource testConf = new GroupOSCOREGroupConfigurationResource(
        													"gp500", CBORObject.NewMap(),
        													this.groupConfigurationResources,
        													this.existingGroupInfo);
        testConf.getConfigurationParameters().Add(GroupcommParameters.GROUP_NAME, CBORObject.FromObject("gp500"));
        this.groupConfigurationResources.put("gp500", testConf);
        // ============
        
    }

    @Override
    public synchronized void handleGET(CoapExchange exchange) {
    	
    	System.out.println("GET request reached the GM at /" + groupCollectionResourcePath);
        
    	// Process the request for retrieving the full list of Group Configurations
    	
    	String subject = null;
    	String errorString = null;
    	
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	errorString = new String("Unauthenticated client tried to get access");
        	System.err.println(errorString);
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorString);
        	return;
        }
        
    	// Check that at least one scope entry in the access token allows the "List" admin permission
    	CBORObject[] permissionSetToken = Util.getGroupOSCOREAdminPermissionsFromToken(subject, null);
    	if (permissionSetToken == null) {
        	errorString = new String("Operation not permitted");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
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
    		
    		auxString += "<" + request.getURI() + "/" + groupName + ">;rt=\"core.osc.gconf\"";
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

    	System.out.println("FETCH request reached the GM at /" + groupCollectionResourcePath);
        
    	// Process the request for retrieving a list of Group Configurations by filters
    	
    	String subject = null;
    	String errorString = null;
    	
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	errorString = new String("Unauthenticated client tried to get access");
    		System.err.println(errorString);
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorString);
        	return;
        }
    	
    	// Check that at least one scope entry in the access token allows the "List" admin permission
    	CBORObject[] permissionSetToken = Util.getGroupOSCOREAdminPermissionsFromToken(subject, null);
    	if (permissionSetToken == null) {
        	errorString = new String("Operation not permitted");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
    		return;
    	}
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null || (requestPayload.length == 0)) {
        	errorString = new String("A payload must be present");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	if(exchange.getRequestOptions().hasContentFormat() == false ||
    	   exchange.getRequestOptions().getContentFormat() != Constants.APPLICATION_ACE_GROUPCOMM_CBOR) {
        	errorString = new String("The CoAP option Content-Format must be present, with value application/ace-groupcomm+cbor");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}

    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
    	
    	// The payload of the request must be a CBOR Map
    	if (!requestCBOR.getType().equals(CBORType.Map)) {
        	errorString = new String("Invalid payload format");
    		System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	for (CBORObject key : requestCBOR.getKeys()) {
    		if (!GroupcommParameters.isAdminRequestParameterMeaningful(key, requestCBOR.get(key))) {
            	errorString = new String("Invalid format of paramemeter with CBOR abbreviation: " + key.AsInt32());
        		System.err.println(errorString);
    			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    			return;
    		}
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
        		auxString += "<" + request.getURI() + "/" + groupName + ">;rt=\"core.osc.gconf\"";
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
        
    	System.out.println("POST request reached the GM at /" + groupCollectionResourcePath);
    	
    	// Process the request for creating a new Group Configuration
    	
    	String subject = null;
    	String errorString = null;
    	
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	errorString = new String("Unauthenticated client tried to get access");
        	System.err.println(errorString);
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorString);
        	return;
        }
        
    	// Check that at least one scope entry in the access token allows the "Create" admin permission
        boolean permitted = false;
    	CBORObject[] adminScopeEntries = Util.getGroupOSCOREAdminPermissionsFromToken(subject, null);
    	if (adminScopeEntries == null) {
        	errorString = new String("Operation not permitted");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
    		return;
    	}
    	for (int i = 0; i < adminScopeEntries.length; i++) {
    		try {
        		short permissions = (short) adminScopeEntries[i].get(1).AsInt32(); 
        		permitted = Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_CREATE);
			} catch (AceException e) {
				System.err.println("Error while verifying the admin permissions: " + e.getMessage());
			}
    		if (permitted) {
    			break;
    		}
    	}
    	if (!permitted) {
        	errorString = new String("Operation not permitted");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
    		return;
    	}
    	
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null || (requestPayload.length == 0)) {
        	errorString = new String("A payload must be present");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	if(exchange.getRequestOptions().hasContentFormat() == false ||
    	   exchange.getRequestOptions().getContentFormat() != Constants.APPLICATION_ACE_GROUPCOMM_CBOR) {
        	errorString = new String("The CoAP option Content-Format must be present, with value application/ace-groupcomm+cbor");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}

    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
    	
    	// The payload of the request must be a CBOR Map
    	if (!requestCBOR.getType().equals(CBORType.Map)) {
        	errorString = new String("Invalid payload format");
    		System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	// The payload of the request must include the status parameter 'group_name'
    	if (!requestCBOR.getKeys().contains(GroupcommParameters.GROUP_NAME)) {
    		errorString = new String("The status parameter 'group_name' must be present");
    		System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	// The payload of the request must not include:
    	// - The status parameters 'rt', 'ace_groupcomm_profile', and 'joining_uri'
    	// - The parameters 'conf_filter' and 'app_groups_diff', as not pertaining to this request
    	if (requestCBOR.getKeys().contains(GroupcommParameters.RT) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.ACE_GROUPCOMM_PROFILE) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.JOINING_URI) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.CONF_FILTER) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.APP_GROUPS_DIFF)) {
    		errorString = new String("Invalid set of parameters in the request");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	// This Group Manager does not support RSA an signature algorithm
    	if (requestCBOR.getKeys().contains(GroupcommParameters.SIGN_ALG)) {
    		CBORObject signAlg = requestCBOR.get(GroupcommParameters.SIGN_ALG);
    		if (signAlg.equals(AlgorithmID.RSA_PSS_256.AsCBOR()) ||
    			signAlg.equals(AlgorithmID.RSA_PSS_384.AsCBOR()) ||
    			signAlg.equals(AlgorithmID.RSA_PSS_512.AsCBOR())) {
    			
    		}
    		CBORObject myResponse = CBORObject.NewMap();
    		errorString = new String("RSA is not supported as signature algorithm");
    		myResponse.Add(GroupcommParameters.ERROR, GroupcommErrors.UNSUPPORTED_GROUP_CONF);
    		myResponse.Add(GroupcommParameters.ERROR_DESCRIPTION, errorString);
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, myResponse.EncodeToBytes(), Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
    	}
    	
    	for (CBORObject key : requestCBOR.getKeys()) {
    		if (!GroupcommParameters.isAdminRequestParameterMeaningful(key, requestCBOR.get(key))) {
    			errorString = new String("Malformed or unrecognized paramemeter with CBOR abbreviation: " + key.AsInt32());
    			System.err.println(errorString);
    			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    			return;
    		}
    	}

    	CBORObject ret = createNewGroupConfiguration(request, adminScopeEntries);
    	    	
    	// Respond to the request for creating a new Group Configuration
        
    	ResponseCode responseCode = CoAP.ResponseCode.valueOf(ret.get(0).AsInt32());
    	Response coapResponse = new Response(responseCode);
    	if (ret.get(1) != null) {
    		int contentFormat = ret.get(1).AsInt32();
        	coapResponse.getOptions().setContentFormat(contentFormat);
    	}
    	byte[] responsePayload = null;
    	if (ret.get(2) == null) {
    		responsePayload = Bytes.EMPTY;
    	}
    	else if (ret.get(2).getType() == CBORType.Map) {
    		responsePayload = ret.get(2).EncodeToBytes();
    	}
    	else if (ret.get(2).getType() == CBORType.TextString) {
    		responsePayload = ret.get(2).AsString().getBytes(Constants.charset);
    	}
    	coapResponse.setPayload(responsePayload);

    	exchange.respond(coapResponse);
    	
    }
    
	/**
     * Create a new group-configuration resource
     * 
     * @param requestCBOR  the POST request to the group-collection resource
     * @param adminScopeEntries  the adminScopeEntries retrieved from the access token for the requester Administrator
     * @return  a CBOR array with three elements, in this order
     * 			- The CoAP response code for the response to the Administrator, as a CBOR integer
     * 			- The CoAP Content-Format to use in the response to the Administrator, as a CBOR integer. It can be null
     * 			- The payload for the response to the Administrator, as a CBOR map or a CBOR text string. It can be null
     * 
     */
    private CBORObject createNewGroupConfiguration(final Request request, final CBORObject[] adminScopeEntries) {
    	
    	String groupName = null;
    	CBORObject ret = CBORObject.NewArray();
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(request.getPayload());

    	// Build a preliminary group configuration, with the final name still to be determined
    	CBORObject buildOutput = GroupOSCOREGroupConfigurationResource.buildGroupConfiguration(requestCBOR, null);
    	
    	// In case of failure, return the information to return an error response to the Administrator
    	if (buildOutput.size() == 3) {

    		for (int i = 0; i < buildOutput.size(); i++) {
    			ret.Add(buildOutput.get(i));
    		}
    		return ret;
    	}
    	
    	// Determine the group name to use
    	String proposedName = requestCBOR.get(GroupcommParameters.GROUP_NAME).AsString();
    	groupName = allocateGroupName(proposedName, adminScopeEntries);
    	
    	if (groupName == null) {
    		// No available and suitable name could be allocated for the new group.
    		//
    		// Return the information for replying with an error response.
    		ret.Add(CoAP.ResponseCode.INTERNAL_SERVER_ERROR.value);
    		ret.Add(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		CBORObject payloadCBOR = CBORObject.NewMap();
    		payloadCBOR.Add(GroupcommParameters.ERROR, GroupcommErrors.GROUP_NAME_NOT_DETERMINED);
    		ret.Add(payloadCBOR);
    		return ret;
    	}
    	
    	// The new name is available and suitable. Add the group configuration to the collection
    	
    	// Complete the group configuration with the selected group name
    	CBORObject groupConfiguration = buildOutput.get(3);
    	groupConfiguration.Add(GroupcommParameters.GROUP_NAME, groupName);
    	
    	// Complete the group configuration with the URI of the associated group-membership resource
    	String requestUri = request.getURI();
    	int index = requestUri.lastIndexOf(super.getURI());
    	String baseUri = request.getURI().substring(0, index + 1);
    	String joiningUri = baseUri + rootGroupMembershipResourcePath + "/" + groupName;
    	groupConfiguration.Add(GroupcommParameters.JOINING_URI, joiningUri);
    	
    	// Complete the group configuration with the URI of the associated Authorization Server
    	groupConfiguration.Add(GroupcommParameters.AS_URI, this.asUri);
    	
    	GroupOSCOREGroupConfigurationResource groupConfigurationResource = null;
    	
    	synchronized(groupConfigurationResources) {
            groupConfigurationResource =  new GroupOSCOREGroupConfigurationResource(groupName, groupConfiguration,
            																		this.groupConfigurationResources,
														  							this.existingGroupInfo);
            groupConfigurationResources.put(groupName, groupConfigurationResource);
            	
    	}

    	Set<Short> actions = new HashSet<>();
    	actions.add(Constants.GET);
    	actions.add(Constants.FETCH);
    	actions.add(Constants.PUT);
    	actions.add(Constants.PATCH);
    	actions.add(Constants.iPATCH);
    	actions.add(Constants.DELETE);
    	this.myScopes.get(groupCollectionResourcePath).put(groupCollectionResourcePath + "/" + groupName, actions);
    	
    	try {
			this.valid.setGroupAdminResources(Collections.singleton(groupCollectionResourcePath + "/" + groupName));
		} catch (AceException e) {
			groupConfigurationResources.remove(groupName); // rollback
			myScopes.get(groupCollectionResourcePath).remove(groupCollectionResourcePath + "/" + groupName); // rollback
			
			String errorString = new String ("Error while initializing the group-configuration resource");			
    		ret.Add(CoAP.ResponseCode.INTERNAL_SERVER_ERROR.value);
    		ret.Add(null);
    		CBORObject payloadCBOR = CBORObject.FromObject(errorString);
    		ret.Add(payloadCBOR);
    		System.err.println(errorString + "\n" + e.getMessage());
    		return ret;
		}

    	this.add(groupConfigurationResource);
    	
    	
    	// Create the group-membership resource and make it actually accessible
    	
    	createGroupMembershipResource(groupConfigurationResource.getConfigurationParameters());
    	
    	
    	// Finalize the payload for the response to the Administrator
    	
    	CBORObject finalPayloadCBOR = CBORObject.NewMap();
    	
    	finalPayloadCBOR = buildOutput.get(2);    	
    	finalPayloadCBOR.Add(GroupcommParameters.GROUP_NAME, groupName);
    	finalPayloadCBOR.Add(GroupcommParameters.JOINING_URI, joiningUri);
    	finalPayloadCBOR.Add(GroupcommParameters.AS_URI, this.asUri);
    	
    	ret.Add(buildOutput.get(0));
    	ret.Add(buildOutput.get(1));
    	ret.Add(finalPayloadCBOR);
    	
    	return ret;
    	
    }

	/**
     * Try to find an alternative name for a new group to be created
     * 
     * @param proposedGroupName  the group name originally proposed in the POST request from the Administrator
     * @param adminScopeEntries  the adminScopeEntries retrieved from the access token for the requester Administrator
     * @return  the new, alternative name to assign to the group, or null if it was not possible to determine one
     * 
     */
    private String allocateGroupName(final String proposedGroupName, final CBORObject[] adminScopeEntries) {
    	
    	String newName = null;
    	
    	synchronized (groupConfigurationResources) {
    		
        	if (!groupConfigurationResources.containsKey(proposedGroupName)) {
        		// The proposed name is available.
        		
        		// Check if there is at least one scope entry such that the name matches the name pattern
        		// and the set of permissions includes the "Create" admin permission
        		boolean permitted = false;
        		
        		for (int i = 0; i < adminScopeEntries.length; i++) {
        		    try {
        		        short permissions = (short) adminScopeEntries[i].get(1).AsInt32();
        		        if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_CREATE)) {
        		        	permitted = Util.matchingGroupOscoreName(proposedGroupName, adminScopeEntries[i].get(0));
        		        }
        		    } catch (AceException e) {
        		        System.err.println("Error while verifying the admin permissions: " + e.getMessage());
        		    }
        		    if (permitted) {
        		        break;
        		    }
        		}
        		if (permitted) {
	        		// Reserve the proposed name, by adding a dummy entry
	        		// in the collection of group-configuration resources
	        		newName = new String(proposedGroupName);
	        		groupConfigurationResources.put(newName, null);
	        		return newName;
        		}
        	}
        	// The proposed name is not available. Try to find a new one.
        	
        	// TBD
    		
    	}
    	
    	return newName;
    	
    }
    
    /**
      * Create a new group-membership resource, following the creation of the corresponding group-configuration resource
      * 
      * @param groupConfiguration  the group configuration
      * 
      * @return  true if the creation succeeds, false otherwise
     */
    private boolean createGroupMembershipResource(final CBORObject groupConfiguration) {
    	
    	String groupName = groupConfiguration.get(GroupcommParameters.GROUP_NAME).AsString();
    	
    	// Include a new scope associated with the new group-membership resource and its sub-resources
    	
    	Map<String, Set<Short>> scopeDescription = new HashMap<>();
    	Set<Short> actions = new HashSet<>();
    	actions.add(Constants.FETCH);
    	scopeDescription.put(rootGroupMembershipResourcePath, actions);
    	actions = new HashSet<>();
    	actions.add(Constants.GET);
    	actions.add(Constants.POST);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName, actions);
    	actions = new HashSet<>();
    	actions.add(Constants.GET);
    	actions.add(Constants.FETCH);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/creds", actions);
    	actions = new HashSet<>();
    	actions.add(Constants.GET);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/kdc-cred", actions);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/verif-data", actions);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/num", actions);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/active", actions);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/policies", actions);
    	actions = new HashSet<>();
    	actions.add(Constants.FETCH);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/stale-sids", actions);
    	myScopes.put(rootGroupMembershipResourcePath + "/" + groupName, scopeDescription);
    	
    	
    	// Mark the new group-membership resource and its sub-resources as such for the access Validator
    	
    	try {
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/creds"));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/kdc-cred"));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/verif-data"));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/num"));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/active"));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/policies"));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/stale-sids"));
    	}
    	catch (AceException e) {
    		System.err.println("Error while verifying the admin permissions: " + e.getMessage());
    		return false;
    	}
    	
    	
    	// Create the actual associated group-membership resource and its sub-resources

    	// Group-membership resource - The name of the OSCORE group is used as resource name
    	Resource groupMembershipResource = new GroupOSCOREGroupMembershipResource(groupName,
    	                                                                          this.existingGroupInfo,
    	                                                                          rootGroupMembershipResourcePath,
    	                                                                          this.myScopes,
    	                                                                          this.valid);
    	// Add the /creds sub-resource
    	Resource credsSubResource = new GroupOSCORESubResourceCreds("creds", existingGroupInfo);
    	groupMembershipResource.add(credsSubResource);

    	// Add the /kdc-cred sub-resource
    	Resource kdcCredSubResource = new GroupOSCORESubResourceKdcCred("kdc-cred", existingGroupInfo);
    	groupMembershipResource.add(kdcCredSubResource);

    	// Add the /verif-data sub-resource
    	Resource verifDataSubResource = new GroupOSCORESubResourceVerifData("verif-data", existingGroupInfo);
    	groupMembershipResource.add(verifDataSubResource);

    	// Add the /num sub-resource
    	Resource numSubResource = new GroupOSCORESubResourceNum("num", existingGroupInfo);
    	groupMembershipResource.add(numSubResource);

    	// Add the /active sub-resource
    	Resource activeSubResource = new GroupOSCORESubResourceActive("active", existingGroupInfo);
    	groupMembershipResource.add(activeSubResource);

    	// Add the /policies sub-resource
    	Resource policiesSubResource = new GroupOSCORESubResourcePolicies("policies", existingGroupInfo);
    	groupMembershipResource.add(policiesSubResource);

    	// Add the /stale-sids sub-resource
    	Resource staleSidsSubResource = new GroupOSCORESubResourceStaleSids("stale-sids", existingGroupInfo);
    	groupMembershipResource.add(staleSidsSubResource);

    	// Add the /nodes sub-resource, as root to actually accessible per-node sub-resources
    	Resource nodesSubResource = new GroupOSCORESubResourceNodes("nodes");
    	groupMembershipResource.add(nodesSubResource);
    	
    	
    	// Create the GroupInfo object according to the group configuration
    	
    	final byte[] masterSecret = new byte[16];
    	try {
			SecureRandom.getInstanceStrong().nextBytes(masterSecret);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating the OSCORE Master Secret for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final byte[] masterSalt = new byte[8];
    	try {
			SecureRandom.getInstanceStrong().nextBytes(masterSalt);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating the OSCORE Master Salt for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final AlgorithmID hkdf;
    	try {
			hkdf = AlgorithmID.FromCBOR(groupConfiguration.get(GroupcommParameters.HKDF));
		} catch (CoseException e) {
			System.err.println("Error when setting the HKDF Algorithm for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final int credFmt = groupConfiguration.get(GroupcommParameters.CRED_FMT).AsInt32();
    	
    	final AlgorithmID gpEncAlg;
    	try {
			gpEncAlg = AlgorithmID.FromCBOR(groupConfiguration.get(GroupcommParameters.GP_ENC_ALG));
		} catch (CoseException e) {
			System.err.println("Error when setting the Group Encryption Algorithm for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final AlgorithmID signAlg;
    	try {
			signAlg = AlgorithmID.FromCBOR(groupConfiguration.get(GroupcommParameters.SIGN_ALG));
		} catch (CoseException e) {
			System.err.println("Error when setting the Signature Algorithm for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final CBORObject signParams = groupConfiguration.get(GroupcommParameters.SIGN_PARAMS);

    	final AlgorithmID alg;
    	try {
			alg = AlgorithmID.FromCBOR(groupConfiguration.get(GroupcommParameters.ALG));
		} catch (CoseException e) {
			System.err.println("Error when setting the AEAD Algorithm for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final AlgorithmID ecdhAlg;
    	try {
			ecdhAlg = AlgorithmID.FromCBOR(groupConfiguration.get(GroupcommParameters.ECDH_ALG));
		} catch (CoseException e) {
			System.err.println("Error when setting the Pairwise Key Agreement Algorithm for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final CBORObject ecdhParams = groupConfiguration.get(GroupcommParameters.ECDH_PARAMS);
    	
    	    	
    	// Generate the Group ID, according to the following rationale:
    	//
    	// - The Prefix uniquely identifies an OSCORE group throughout its rekeying occurrences.
    	//   The Prefix size is the same for all the OSCORE groups and is up to 4 bytes.
    	//
    	// - The Epoch of an Group ID changes each time the group is rekeyed. Its size is up to 4 bytes.
    	// - The initial value of Epoch is all zeroes.
    	
    	boolean available = false;
    	byte[] groupIdPrefix = new byte[this.groupIdPrefixSize];
    	byte[] groupIdEpoch = new byte[] { (byte) 0x00, (byte) 0x00 };
    	
    	synchronized (this.usedGroupIdPrefixes) {
    		
        	int sizeLimit = (int) Math.pow(2, this.groupIdPrefixSize);
        	if (this.usedGroupIdPrefixes.size() == sizeLimit) {
        		// Rollback
    			groupConfigurationResources.remove(groupName);
    			myScopes.get(groupCollectionResourcePath).remove(groupCollectionResourcePath + "/" + groupName);
        		
    			System.err.println("No available Group IDs for creating the OSCORE group with name \"" + groupName + "\"");
    			return false;
        	}
        	        	
        	CBORObject groupIdPrefixCbor = null;
        	while(available == false) {
            	try {
        			SecureRandom.getInstanceStrong().nextBytes(groupIdPrefix);
        		} catch (NoSuchAlgorithmException e) {
        			System.err.println("Error when generating the OSCORE Group ID for the OSCORE group with name \"" + groupName + "\"");
        			e.printStackTrace();
        			return false;
        		}
            	groupIdPrefixCbor = CBORObject.FromObject(groupIdPrefix);
            	available = (this.usedGroupIdPrefixes.contains(groupIdPrefixCbor) == false);
        	}
        	
        	this.usedGroupIdPrefixes.add(groupIdPrefixCbor);
        	
    	}

    	// Set the asymmetric key pair and public key of the Group Manager
    	
    	// Serialization of the COSE Key including both private and public part
    	byte[] gmKeyPairBytes = null;
    	
    	CBORObject curve = null;
    	boolean useGroupMode = groupConfiguration.get(GroupcommParameters.GROUP_MODE).AsBoolean();
    	
    	if (useGroupMode) {
	    	CBORObject keyTypeCBOR = groupConfiguration.get(GroupcommParameters.SIGN_PARAMS).get(0).get(0);
	    	if (keyTypeCBOR.equals(COSE.KeyKeys.KeyType_OKP) || keyTypeCBOR.equals(COSE.KeyKeys.KeyType_EC2)) {
	    		curve = groupConfiguration.get(GroupcommParameters.SIGN_PARAMS).get(1).get(1);
	    		
	    		if (curve.AsInt32() == COSE.KeyKeys.EC2_P256.AsInt32()) {
	    			gmKeyPairBytes = Utils.hexToBytes( gmSigningKeyPairs.get(COSE.KeyKeys.EC2_P256));
	    		}
	    		if (curve.AsInt32() == COSE.KeyKeys.OKP_Ed25519.AsInt32()) {
	    			gmKeyPairBytes = Utils.hexToBytes( gmSigningKeyPairs.get(COSE.KeyKeys.OKP_Ed25519));
	    		}
	    	}
    	}
    	else {
    		// This group uses only the pairwise mode, thus the authentication credential
    		// of the Group Manager has to be specific for key agreement operations
	    	CBORObject keyTypeCBOR = groupConfiguration.get(GroupcommParameters.ECDH_PARAMS).get(0).get(0);
	    	if (keyTypeCBOR.equals(COSE.KeyKeys.KeyType_OKP) || keyTypeCBOR.equals(COSE.KeyKeys.KeyType_EC2)) {
	    		curve = groupConfiguration.get(GroupcommParameters.ECDH_PARAMS).get(1).get(1);
	    		
	    		if (curve.AsInt32() == COSE.KeyKeys.EC2_P256.AsInt32()) {
	    			gmKeyPairBytes = Utils.hexToBytes( gmKeyAgreementKeyPairs.get(COSE.KeyKeys.EC2_P256));
	    		}
	    		if (curve.AsInt32() == COSE.KeyKeys.OKP_X25519.AsInt32()) {
	    			gmKeyPairBytes = Utils.hexToBytes( gmKeyAgreementKeyPairs.get(COSE.KeyKeys.OKP_X25519));
	    		}
	    	}
    	}
    	
    	if (curve == null) {
    		// This should never happen
    		
    		// Rollback
			groupConfigurationResources.remove(groupName);
			myScopes.get(groupCollectionResourcePath).remove(groupCollectionResourcePath + "/" + groupName);
    		
			System.err.println("Error when setting up the Group Manager's authentication credential" +
							   "for the OSCORE group with name \"" + groupName + "\"");
			return false;
    	}
    	

    	OneKey gmKeyPair = null;
    	try {
			gmKeyPair = new OneKey(CBORObject.DecodeFromBytes(gmKeyPairBytes));
		} catch (CoseException e) {
    		// Rollback
			groupConfigurationResources.remove(groupName);
			myScopes.get(groupCollectionResourcePath).remove(groupCollectionResourcePath + "/" + groupName);
    		
			System.err.println("Error when setting up the Group Manager's authentication credential" +
							   "for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			
			return false;
		}
    	
    	
    	// Serialization of the authentication credential, according to the format used in the group
    	byte[] gmAuthCred = null;
    	
    	
    	// Build the authentication credential according to the format used in the group
    	switch (credFmt) {
	        case Constants.COSE_HEADER_PARAM_KCCS:
	            // A CCS including the public key
	        	if (curve.AsInt32() == COSE.KeyKeys.EC2_P256.AsInt32()) {
	        		if (useGroupMode) {
	        			gmAuthCred = Utils.hexToBytes(gmSigningPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS).get(COSE.KeyKeys.EC2_P256));
		        		// gmAuthCred = Utils.hexToBytes("A2026008A101A50102032620012158202236658CA675BB62D7B24623DB0453A3B90533B7C3B221CC1C2C73C4E919D540225820770916BC4C97C3C46604F430B06170C7B3D6062633756628C31180FA3BB65A1B");
	        		}
	        		else {
	        			gmAuthCred = Utils.hexToBytes(gmKeyAgreementPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS).get(COSE.KeyKeys.EC2_P256));
	        		}		
	        	}
	        	if (curve.AsInt32() == COSE.KeyKeys.OKP_Ed25519.AsInt32()) {
	        		gmAuthCred = Utils.hexToBytes(gmSigningPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS).get(COSE.KeyKeys.OKP_Ed25519));
	        		// gmAuthCred = Utils.hexToBytes("A2026008A101A4010103272006215820C6EC665E817BD064340E7C24BB93A11E8EC0735CE48790F9C458F7FA340B8CA3");
	        	}
	        	if (curve.AsInt32() == COSE.KeyKeys.OKP_X25519.AsInt32()) {
	        		gmAuthCred = Utils.hexToBytes(gmKeyAgreementPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS).get(COSE.KeyKeys.OKP_X25519));
	        	}
	            break;
	        case Constants.COSE_HEADER_PARAM_KCWT:
	            // A CWT including the public key
	            // TODO
	        	gmAuthCred = null;
	            break;
	        case Constants.COSE_HEADER_PARAM_X5CHAIN:
	            // A certificate including the public key
	            // TODO
	        	gmAuthCred = null;
	            break;
    	}
    	
    	int mode = GroupcommParameters.GROUP_OSCORE_GROUP_PAIRWISE_MODE;
    	boolean usePairwiseMode = groupConfiguration.get(GroupcommParameters.PAIRWISE_MODE).AsBoolean();
    	if (useGroupMode == true && usePairwiseMode == true) {
    		mode = GroupcommParameters.GROUP_OSCORE_GROUP_PAIRWISE_MODE;
    	}
    	else if (useGroupMode == true && usePairwiseMode == false) {
    		mode = GroupcommParameters.GROUP_OSCORE_GROUP_MODE_ONLY;
    	}
    	else if (useGroupMode == false && usePairwiseMode == true) {
    		mode = GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY;
    	}
    	
    	GroupInfo myGroupInfo = new GroupInfo(groupName,
										      masterSecret,
										      masterSalt,
										      groupIdPrefixSize,
										      groupIdPrefix,
										      groupIdEpoch.length,
										      Util.bytesToInt(groupIdEpoch),
										      prefixMonitorNames,
										      nodeNameSeparator,
										      hkdf,
										      credFmt,
										      mode,
										      gpEncAlg,
										      signAlg,
										      signParams,
										      alg,
										      ecdhAlg,
										      ecdhParams,
										      null,
										      gmKeyPair,
										      gmAuthCred,
										      maxStaleIdsSets);
    	
    	boolean initialStatus = groupConfiguration.get(GroupcommParameters.ACTIVE).AsBoolean();
    	myGroupInfo.setStatus(initialStatus);
    	
		// Store the information on this OSCORE group
    	this.existingGroupInfo.put(groupName, myGroupInfo);
    	
    	// Finally make the group-membership resource accessible
    	this.groupOSCORERootGroupMembership.add(groupMembershipResource);
    	
    	return true;
    	
    }

}
