/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.security;

import org.apache.hadoop.security.authentication.server.SmartAuthenticationFilter;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.http.FilterContainer;
import org.apache.hadoop.http.FilterInitializer;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.HashMap;
import java.util.Map;

/**
 * Initializes a modified version of Alfredo's AuthenticationFilter which provides support for
 * Kerberos HTTP SPENGO authentication.
 * <p/>
 * It enables anonymous access, simple/speudo and Kerberos HTTP SPNEGO
 * authentication  for Hadoop JobTracker, NameNode, DataNodes and
 * TaskTrackers.
 * <p/>
 * Refer to the <code>core-default.xml</code> file, after the comment
 * 'HTTP Authentication' for details on the configuration options.
 * All related configuration properties have 'hadoop.http.authentication.'
 * as prefix.
 */
public class SmartAuthenticationFilterInitializer extends FilterInitializer {

  static final String PREFIX = "hadoop.http.authentication.";

  static final String SIGNATURE_SECRET_FILE = SmartAuthenticationFilter.SIGNATURE_SECRET + ".file";

  /**
   * Initializes a modified Alfredo AuthenticationFilter called
   * SmartAuthenticationFilter.
   * <p/>
   * Propagates to SmartAuthenticationFilter configuration all Hadoop
   * configuration properties prefixed with "hadoop.http.authentication."
   *
   * @param container The filter container
   * @param conf Configuration for run-time parameters
   */
  @Override
  public void initFilter(FilterContainer container, Configuration conf) {
    Map<String, String> filterConfig = new HashMap<String, String>();

    //setting the cookie path to root '/' so it is used for all resources.
    filterConfig.put(SmartAuthenticationFilter.COOKIE_PATH, "/");

    for (Map.Entry<String, String> entry : conf) {
      String name = entry.getKey();
      if (name.startsWith(PREFIX)) {
        String value = conf.get(name);
        name = name.substring(PREFIX.length());
        filterConfig.put(name, value);
      }
    }

    String signatureSecretFile = filterConfig.get(SIGNATURE_SECRET_FILE);
    if (signatureSecretFile == null) {
      signatureSecretFile = System.getProperty("user.home")+System.getProperty("file.separator")+System.getProperty("user.name") + ".http-auth-signature-secret";
    }

    try {
      StringBuilder secret = new StringBuilder();
      Reader reader = new FileReader(signatureSecretFile);
      int c = reader.read();
      while (c > -1) {
        secret.append((char)c);
        c = reader.read();
      }
      reader.close();
      filterConfig.put(SmartAuthenticationFilter.SIGNATURE_SECRET, secret.toString());
    } catch (IOException ex) {
      throw new RuntimeException("Could not read HTTP signature secret file: " + signatureSecretFile);
    }

    container.addFilter("authentication",
                        SmartAuthenticationFilter.class.getName(),
                        filterConfig);
  }

}
