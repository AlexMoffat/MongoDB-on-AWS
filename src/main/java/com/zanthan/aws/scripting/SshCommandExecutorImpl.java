package com.zanthan.aws.scripting;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Execute a command on a remote machine using the ssh
 * command installed locally.
 *
 * @author amoffat Alex Moffat
 */
public class SshCommandExecutorImpl
        implements SshCommandExecutor {

    /**
     * Name of the file containing the private key
     * to authorize access to run the command.
     */
    private final String keyFile;

    /**
     * Name of the file containing information
     * about hosts we've connected to.
     */
    private final String hostsFile;

    /**
     * Create a new instance.
     *
     * @param keyFile File containing private key.
     * @param hostsFile File of hosts we've contacted.
     */
    public SshCommandExecutorImpl(File keyFile, File hostsFile) {
        this.keyFile = keyFile.getPath();
        this.hostsFile = hostsFile.getPath();
    }

    /**
     * Execute the command on the remote user and machine
     * identified by the address and provide its output
     * to the output handler.
     *
     * @param address Address, something like foo@bar.com
     * @param command The command to execute.
     * @param outputHandler Object to receive the output.
     * @throws IOException
     */
    public void execute(String address, String command,
                        OutputHandler outputHandler)
            throws IOException {

        // Execute the command to create a process.
        Process p = execute(address, command);

        // Read all of the output from the process.
        BufferedReader rdr = new BufferedReader(new InputStreamReader(p.getInputStream()));
        try {
            String line;
            while ((line = rdr.readLine()) != null) {
                outputHandler.handle(line);
            }
        } finally {
            rdr.close();
        }
    }

    /**
     * Execute the command on the remote user and machine
     * identified by the address and return the process.
     *
     * @param address Address (user plus machine) to execute command on.
     * @param command The command.
     * @return SSH process.
     * @throws IOException
     */
    private Process execute(String address, String command)
            throws IOException {

        ProcessBuilder pb = new ProcessBuilder(
                "ssh",
                "-i", keyFile,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=" + hostsFile,
                address,
                command
        );
        pb.redirectErrorStream(true);

        return pb.start();
    }
}
