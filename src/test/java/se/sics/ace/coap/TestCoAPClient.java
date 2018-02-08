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
package se.sics.ace.coap;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.InetSocketAddress;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.CoapEndpointBuilder;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.OneKey;
import se.sics.ace.Constants;
import se.sics.ace.ReferenceToken;
import se.sics.ace.as.DBConnector;
import se.sics.ace.as.Token;

/**
 * Test the coap classes.
 * 
 * NOTE: This will automatically start a server in another thread
 * 
 * @author Ludwig Seitz
 *
 */
public class TestCoAPClient {
    
    static byte[] key256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    static String aKey = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";
    static RunTestServer srv = null;
    
    private static class RunTestServer implements Runnable {
        
        public RunTestServer() {
           //Do nothing
        }

        /**
         * Stop the server
         * @throws Exception 
         */
        public void stop() throws Exception {
            TestCoAPServer.stop();
        }
        
        @Override
        public void run() {
            try {
                TestCoAPServer.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                try {
                    TestCoAPServer.stop();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        
    }
    
    
    /**
     * This sets up everything for the tests including the server
     */
    @BeforeClass
    public static void setUp() {
        srv = new RunTestServer();
        srv.run();
    }
    
    /**
     * Deletes the test DB after the tests
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        srv.stop();
        String dbPwd = null;
        BufferedReader br = new BufferedReader(new FileReader("db.pwd"));
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            dbPwd = sb.toString().replace(
                    System.getProperty("line.separator"), "");     
        } finally {
            br.close();
        }
        Properties connectionProps = new Properties();
        connectionProps.put("user", "root");
        connectionProps.put("password", dbPwd);
        Connection rootConn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306", connectionProps);

        String dropDB = "DROP DATABASE IF EXISTS " + DBConnector.dbName + ";";
        String dropUser = "DROP USER 'aceuser'@'localhost';";
        Statement stmt = rootConn.createStatement();
        stmt.execute(dropDB);
        stmt.execute(dropUser);    
        stmt.close();
        rootConn.close();   
    }
    
    /**
     * Test connecting with RPK without authenticating the client.
     * The Server should reject that.
     * 
     * @throws Exception 
     */
    @Test
    public void testNoClientAuthN() throws Exception {
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        builder.setClientOnly();
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        CoapEndpointBuilder ceb = new CoapEndpointBuilder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient("coaps://localhost/introspect");
        client.setEndpoint(e);
        dtlsConnector.start();

        ReferenceToken at = new ReferenceToken(new byte[]{0x00});
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.TOKEN, at.encode());
        try {
            client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        } catch (RuntimeException ex) {
            Object cause = ex.getCause();
            if (cause instanceof HandshakeException) {
                HandshakeException he = (HandshakeException)cause;
                System.out.println(he.getAlert().toString());
                //Everything ok
                return;
            }
        }
        
        Assert.fail("Server should not accept DTLS connection");       
    }
    
    
    /**
     * Test CoapToken using PSK
     * 
     * @throws Exception 
     */
    @Test
    public void testCoapToken() throws Exception {
        OneKey asymmetricKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        builder.setPskStore(new StaticPskStore("clientA", key256));
        builder.setIdentity(asymmetricKey.AsPrivateKey(), 
                asymmetricKey.AsPublicKey());
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        CoapEndpointBuilder ceb = new CoapEndpointBuilder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient("coaps://localhost/token");
        client.setEndpoint(e);
        dtlsConnector.start();

        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, 
                CBORObject.FromObject("r_temp rw_config foobar"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);    
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        System.out.println(map);
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("r_temp rw_config"));
    }
    
    /**
     * Test CoapIntrospect using RPK
     * 
     * @throws Exception
     */
    @Test
    public void testCoapIntrospect() throws Exception {
        OneKey key = new OneKey(
                CBORObject.DecodeFromBytes(Base64.getDecoder().decode(aKey)));
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        //builder.setPskStore(new StaticPskStore("rs1", key256));
        builder.setIdentity(key.AsPrivateKey(), 
                key.AsPublicKey());
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());

        CoapEndpointBuilder ceb = new CoapEndpointBuilder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient("coaps://localhost/introspect");
        client.setEndpoint(e);
        dtlsConnector.start();
       
        ReferenceToken at = new ReferenceToken(new byte[]{0x00});
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.TOKEN, at.encode());
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        System.out.println(map);
        assert(map.containsKey(Constants.AUD));
        assert(map.get(Constants.AUD).AsString().equals("actuators"));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("co2"));
        assert(map.containsKey(Constants.ACTIVE));
        assert(map.get(Constants.ACTIVE).isTrue());
        assert(map.containsKey(Constants.CTI));
        assert(map.containsKey(Constants.EXP));
        
    }
}
