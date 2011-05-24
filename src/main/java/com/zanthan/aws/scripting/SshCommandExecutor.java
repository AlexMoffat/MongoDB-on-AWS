package com.zanthan.aws.scripting;

import java.io.IOException;

/**
 * Interface for executing commands remotely using SSH.
 *
 * @author amoffat Alex Moffat
 */
public interface SshCommandExecutor {

    /**
     * Execute a command on a machine that we log onto using address.
     * The lines output by the command, both stdout and stderr,
     * is provided to the output handler.
     *
     * @param address Address, something like foo@bar.com
     * @param command The command to execute.
     * @param outputHandler Object to receive the output.
     * @throws IOException In case of errors.
     */
    public void execute(String address, String command,
                        OutputHandler outputHandler)
            throws IOException;

    /**
     * Interface used to receive output from executing
     * a command.
     */
    public interface OutputHandler {

        /**
         * Handle a single line of output.
         *
         * @param line The line.
         */
        public void handle(String line);
    }
}
