package com.zanthan.aws.scripting;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.BlockDeviceMapping;
import com.amazonaws.services.ec2.model.DescribeInstancesRequest;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.EbsBlockDevice;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.Placement;
import com.amazonaws.services.ec2.model.RunInstancesRequest;
import com.amazonaws.services.ec2.model.RunInstancesResult;

/**
 * Create a new MongoDB replica set using two Amazon EC2
 * instances. This program has to be run from the correct
 * directory because it uses relative paths for some files.
 * It is deliberately written in a scripting style, the
 * sort of program you might think of writing in Ruby or
 * Python.
 *
 * @author amoffat Alex Moffat
 */
public class StartMongoDBReplicaSet {

    /**
     * Id of the image to use for each of the instances.
     */
    private static final String IMAGE_ID =
            "ami-74f0061d";

    /**
     * Type of instance to use.
     */
    private static final String INSTANCE_TYPE =
            "t1.micro";

    /**
     * Availability zone to start the instances in.
     */
    private static final String AVAILABILITY_ZONE =
            "us-east-1a";

    /**
     * Security group that defines firewall rules for
     * the MongoDB instances.
     */
    private static final String SECURITY_GROUP =
            "MongoDB";

    /**
     * Name of the key pair to use for the instances.
     */
    private static final String KEY_NAME =
            "KeyPair20110224";

    /**
     * Location of the file containing the private key from
     * the key pair used for launching instances.
     */
    private static final String KEY_FILE =
            "keys/KeyPair20110224.pem";

    /**
     * Id of the EBS snapshot containing the MongoDB executables.
     * This will be used to create the disks mounted by the AWS
     * instances.
     */
    private static final String SNAPSHOT_ID =
            "snap-a9c5e0c6";

    /**
     * Name of the device the disks created from the snapshot will
     * be attached to. This is referenced in the MongoDBInit.txt file.
     */
    private static final String DEVICE_NAME =
            "/dev/sdf";

    /**
     * File of CloudInit instructions.
     */
    private static final String LOCAL_USER_DATA_FILE =
            "MongoDBInit.txt";

    /**
     * Command that is executed on each Amazon EC2 instance to start
     * MongoDB. The private ip address of the other machine in the
     * replica set is appended to the command.
     */
    private static final String REMOTE_MONGO_DB_START_CMD =
            "/mongodb/mongodb-linux-x86_64-1.8.1/bin/mongod " +
                    "--dbpath /home/ec2-user/data/db " +
                    "--logpath /home/ec2-user/mongodb.log " +
                    "--nohttpinterface " +
                    "--fork " +
                    "--replSet logSet/";

    /**
     * Path to the local MongoDB mongo executable. This is used
     * to issue the commands to configure the replica set.
     */
    private static final String LOCAL_MONGO_EXECUTABLE =
            "mongodb-osx-x86_64-1.8.1/bin/mongo";

    /**
     * The command to configure the replica set. Need additional
     * single quotes because of Java MessageFormat formatting rules.
     * {0} and {1} are substituted with the private ip addresses
     * of the two machines in the set.
     */
    private static final String START_REPLICASET_CMD =
            "'db.runCommand({\"replSetInitiate\" : {\n" +
                    "\"_id\" : \"logSet\",\n" +
                    "\"members\" : [\n" +
                    "{\n" +
                    "\"_id\" : 1,\n" +
                    "\"host\" : \"'{0}'\"\n" +
                    "},\n" +
                    "{\n" +
                    "\"_id\" : 2,\n" +
                    "\"host\" : \"'{1}'\"\n" +
                    "}\n" +
                    "]}})'";

    /**
     * Start the whole process.
     *
     * @param args Arguments passed to the program are ignored.
     * @throws IOException In the event of an error.
     */
    public static void main(String[] args)
            throws IOException {

        // Create the AmazonEC2 client to communicate with
        AmazonEC2 ec2 = createEC2Client();

        // Create object to execute ssh commands on the
        // EC2 instances started by the program.
        SshCommandExecutor sshCommandExecutor =
                createSSHCommandExecutor();

        // Create the replica set.
       new StartMongoDBReplicaSet(ec2, sshCommandExecutor).run();
    }

    /**
     * Create the object that will use SSH to execute commands
     * on the EC2 instances.
     *
     * @return New executor.
     * @throws IOException If errors occur.
     */
    private static SshCommandExecutor createSSHCommandExecutor()
            throws IOException {

        // Check that the key file we want to use exists.
        File keyFile = new File(KEY_FILE);
        if (!keyFile.exists()) {
            throw new IllegalStateException("Key file " +
                    keyFile.getPath() + " does not exist.");
        }

        // Create a temporary hosts file. The ssh command will
        // automatically add hosts to this file. A new one is
        // used instead of the default one. EC2 reuses IP addresses
        // so you may find you get the different host fingerprints
        // for the same IP over the course of multiple executions.
        // There is no way to tell SSH not to blow up in this case
        // but using a new host file for each replica set guarantees
        // it won't happen.
        File hostsFile = File.createTempFile("Hosts", ".txt");
        hostsFile.deleteOnExit();

        return new SshCommandExecutorImpl(keyFile, hostsFile);
    }

    /**
     * Create Amazon EC2 client to use to communicate with AWS. The
     * AWS_CREDENTIAL_FILE environment variable that is used by the
     * Amazon command line tools is used here to find the access
     * and secret key we need.
     *
     * @return The client.
     * @throws IOException If things go wrong.
     */
    private static AmazonEC2 createEC2Client()
            throws IOException {

        // Find the name of the credentials file and make sure
        // it exists.
        String credentialFileName =
                System.getenv("AWS_CREDENTIAL_FILE");
        if (credentialFileName == null) {
            throw new IllegalStateException("No value for environment " +
                    "variable AWS_CREDENTIAL_FILE");
        }
        File propertiesFile = new File(credentialFileName);
        if (!propertiesFile.exists()) {
            throw new IllegalStateException("Properties file " +
                    propertiesFile.getPath() + " does not exist.");
        }

        // Load the credentials file as a properties file.
        FileReader propertiesReader = new FileReader(propertiesFile);
        Properties awsKeys = new Properties();
        awsKeys.load(propertiesReader);

        // Pull out the correct properties to create the basic
        // credentials we need.
        BasicAWSCredentials credentials =
                new BasicAWSCredentials(awsKeys.getProperty("AWSAccessKeyId"),
                        awsKeys.getProperty("AWSSecretKey"));

        return new AmazonEC2Client(credentials);
    }

    /**
     * Communication with EC2.
     */
    private final AmazonEC2 ec2;

    /**
     * Execute commands on remote hosts using SSH.
     */
    private final SshCommandExecutor sshCommandExecutor;

    /**
     * Create an new object.
     *
     * @param ec2 Communication with EC2.
     * @param sshCommandExecutor Remote command execution
     */
    public StartMongoDBReplicaSet(AmazonEC2 ec2,
                                  SshCommandExecutor sshCommandExecutor) {
        this.ec2 = ec2;
        this.sshCommandExecutor = sshCommandExecutor;
    }

    /**
     * The top level entry point. This is the basic script that sequences
     * the necessary operations.
     *
     * @throws IOException In the event of an error.
     */
    private void run()
            throws IOException {

        // Start the instances.
        List<Instance> instances = startInstances();

        // Even after the instances have started we need
        // to wait a little while for the CloudInit
        // processing to complete so that we can connect
        // to them with SSH.
        waitABit(45, "for initialization to complete.");

        // Get the public and private ip addresses of
        // the two instances.
        String machineOnePublicIp =
                instances.get(0).getPublicIpAddress();
        String machineOnePrivateIp =
                instances.get(0).getPrivateIpAddress();

        String machineTwoPublicIp =
                instances.get(1).getPublicIpAddress();
        String machineTwoPrivateIp =
                instances.get(1).getPrivateIpAddress();

        // Start MongoDB on the first machine.
        startMongoDb(machineOnePublicIp,
                machineTwoPrivateIp);

        // Start MongoDB on the second machine.
        startMongoDb(machineTwoPublicIp,
                machineOnePrivateIp);

        // Wait till everything is ready.
        waitABit(30, "for MongoDB to become available.");

        // Start the replica set. We'll contact machineOne.
        startReplicaSet(machineOnePublicIp,
                machineOnePrivateIp,
                machineTwoPrivateIp);

    }

    /**
     * Start the 2 instances needed for the replica set.
     *
     * @return List of the instances. All will be in the
     * running state.
     * @throws IOException If things go wrong.
     */
    private List<Instance> startInstances()
            throws IOException {

        // New block device to create from snapshot
        // containing MongoDB executables.
        EbsBlockDevice blockDevice =
                new EbsBlockDevice()
                        .withSnapshotId(SNAPSHOT_ID)
                        .withDeleteOnTermination(true);
        // Mapping for the new block device to map it
        // to /dev/sdf
        BlockDeviceMapping blockDeviceMapping =
                new BlockDeviceMapping()
                        .withDeviceName(DEVICE_NAME)
                        .withEbs(blockDevice);
        // Date for CloudInit to use when configuring
        // the started instance.
        String userData = readUserData();
        // Configure the request using the block device
        // mapping, user data and other parameters.
        RunInstancesRequest runRequest =
                new RunInstancesRequest(IMAGE_ID, 2, 2)
                        .withSecurityGroups(SECURITY_GROUP)
                        .withKeyName(KEY_NAME)
                        .withInstanceType(INSTANCE_TYPE)
                        .withPlacement(new Placement(AVAILABILITY_ZONE))
                        .withBlockDeviceMappings(blockDeviceMapping)
                        .withUserData(userData);

        // Ask AWS to start the instances.
        RunInstancesResult runResult = ec2.runInstances(runRequest);

        // Wait for them to start.
        List<Instance> instances =
                waitForInstancesToStart(runResult.getReservation().getInstances());

        System.out.println("Started instances.");

        return instances;
    }

    /**
     * Read the CloudInit configuration data from a file and return it.
     *
     * @return The config data, base64 encoded.
     * @throws IOException If there are problems.
     */
    private String readUserData() throws IOException {
        // Make sure the file exists.
        File dataFile = new File(LOCAL_USER_DATA_FILE);
        if (!dataFile.exists()) {
            throw new IllegalStateException("Can not find ec2 init data file " +
                    dataFile.getPath());
        }
        // Read and convert to base64
        Base64InputStream inputStream =
                new Base64InputStream(new FileInputStream(dataFile), true);
        String userData =
                IOUtils.toString(inputStream);
        inputStream.close();
        return userData;
    }

    /**
     * Wait until all of the instances in the list report their state
     * as running, or 1.5 minutes have elapsed. If they aren't all
     * running after 1.5 minutes and IllegalStateException is thrown.
     *
     * @param instances The instances to check.
     * @return The instances, all in the running state.
     */
    private List<Instance> waitForInstancesToStart(List<Instance> instances) {
        // Number of times we've checked
        int count = 0;
        // Start by checking, just in case.
        boolean allRunning = checkIfAllRunning(instances);
        while (!allRunning && count < 6) {
            // Wait 15 seconds.
            waitABit(15, "for instances to start.");
            // Get the status of the instances by providing
            // a list of their ids.
            DescribeInstancesRequest describeRequest =
                    new DescribeInstancesRequest()
                            .withInstanceIds(extractIds(instances));
            DescribeInstancesResult describeResult =
                    ec2.describeInstances(describeRequest);
            // We know there will be a single reservation.
            instances = describeResult.getReservations()
                    .get(0).getInstances();
            allRunning = checkIfAllRunning(instances);
            ++count;
        }

        if (!allRunning) {
            throw new IllegalStateException("All instances did not start.");
        }
        return instances;
    }

    /**
     * Wait some number of seconds.
     *
     * @param timeInSeconds Number of seconds to wait.
     * @param reason The reason we're waiting.
     */
    private void waitABit(long timeInSeconds, String reason) {
        System.out.println("Waiting " + timeInSeconds + " seconds " +
                reason);
        synchronized (this) {
            try {
                wait(timeInSeconds * 1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * From a list of instances extract a list of their ids.
     *
     * @param instances The instances.
     * @return The ids.
     */
    private List<String> extractIds(List<Instance> instances) {
        List<String> instanceIds =
                new ArrayList<String>(instances.size());
        for (Instance instance : instances) {
            instanceIds.add(instance.getInstanceId());
        }
        return instanceIds;
    }

    /**
     * If all of the instances in the list have a state of "running"
     * return true, otherwise return false.
     *
     * @param instances The instances to check.
     * @return True or false.
     */
    private boolean checkIfAllRunning(List<Instance> instances) {
        System.out.println("Checking that all instances are running.");
        boolean allRunning;
        allRunning = true;
        for (Instance instance : instances) {
            System.out.println("Instance " + instance.getInstanceId() +
                    " is " + instance.getState().getName() + ".");
            if (!"running".equals(instance.getState().getName())) {
                allRunning = false;
            }
        }
        return allRunning;
    }

    /**
     * Start a MongoDB server on first machine telling it that it's part
     * of a replica set that includes second machine. Communication
     * between the members of the replica set is done via their private
     * IP addresses.
     *
     * @param firstMachinePublicIp Public IP of the first machine.
     * @param secondMachinePrivateIp Private IP of the second machine.
     * @throws IOException If errors occur.
     */
    private void startMongoDb(String firstMachinePublicIp,
                              String secondMachinePrivateIp)
            throws IOException {
        // Need to create an address to log on to the first
        // machine.
        String firstMachineAddress = "ec2-user@" +
                firstMachinePublicIp;
        System.out.println("Going to start MongoDB as " +
                firstMachineAddress);

        // Variables to collect results starting MongoDB.
        final String[] processNumber = new String[] {null};
        final StringBuilder sb = new StringBuilder();

        // Number of times we've tried to start MongoDB.
        int count = 0;

        // It may take a while for the instance to be fully initialized
        // and reachable via ssh so try several times.
        while (processNumber[0] == null && count < 4) {
            // Use SSH to issue the command to start MongoDB on
            // the remote machine. Look at the output and if
            // we see "forked process: " assume success.
            sshCommandExecutor.execute(firstMachineAddress,
                    REMOTE_MONGO_DB_START_CMD + secondMachinePrivateIp,
                    new SshCommandExecutor.OutputHandler() {
                        public void handle(String line) {
                            sb.append(line);
                            sb.append('\n');
                            if (line.startsWith("forked process: ")) {
                                processNumber[0] =
                                        line.substring("forked process: ".length()).trim();
                            }
                        }
                    });
            ++count;
            if (processNumber[0] == null) {
                waitABit(30, "for instance to be reachable via ssh.");
            }
        }

        // If we didn't find a process then print out all of
        // the output from SSH and throw an exception.
        if (processNumber[0] == null) {
            System.out.println("Response from starting MongoDB was:");
            System.out.println(sb.toString());
            throw new IllegalStateException("Could not start MongoDB as " +
                    firstMachineAddress);
        }

        System.out.println("MongoDB started process " + processNumber[0] +
                " as " + firstMachineAddress);
    }

    /**
     * Start a MongoDB replica set by contacting the admin database on machine
     * one.
     *
     * @param firstMachinePublicIp Public IP of first machine.
     * @param firstMachinePrivateIp Private IP of first machine.
     * @param secondMachinePrivateIp Private IP of second machine.
     * @throws IOException In the event of error.
     */
    private void startReplicaSet(String firstMachinePublicIp,
                                 String firstMachinePrivateIp,
                                 String secondMachinePrivateIp)
            throws IOException {

        // Substitute the two private ip addresses into the command
        // to start the replica set.
        String cmd =
                MessageFormat.format(START_REPLICASET_CMD,
                        firstMachinePrivateIp, secondMachinePrivateIp);

        // Write the start command into a file with the
        // correct extension.
        File jsFile = File.createTempFile("replicaset", ".js");
        jsFile.deleteOnExit();
        FileUtils.writeStringToFile(jsFile, cmd);

        // Run the command and write out the results.
        ProcessBuilder pb = new ProcessBuilder(
                LOCAL_MONGO_EXECUTABLE,
                firstMachinePublicIp + "/admin",
                jsFile.getPath()
        );
        pb.redirectErrorStream(true);

        Process p = pb.start();

        BufferedReader rdr =
                new BufferedReader(new InputStreamReader(p.getInputStream()));
        try {
            String line;
            while ((line = rdr.readLine()) != null) {
                System.out.println(line);
            }
        } finally {
            rdr.close();
        }
    }
}
