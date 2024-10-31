/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package hudson.cli;

import static java.util.logging.Level.FINE;
import static java.util.logging.Level.parse;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.cli.client.Messages;
import jakarta.websocket.ClientEndpointConfig;
import jakarta.websocket.Endpoint;
import jakarta.websocket.EndpointConfig;
import jakarta.websocket.HandshakeResponse;
import jakarta.websocket.Session;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.MalformedURLException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.apache.commons.io.IOUtils;
import javax.net.ssl.HostnameVerifier;
import org.glassfish.tyrus.client.ClientManager;
import org.glassfish.tyrus.client.ClientProperties;
import org.glassfish.tyrus.client.SslEngineConfigurator;
import org.glassfish.tyrus.client.exception.DeploymentHandshakeException;
import org.glassfish.tyrus.container.jdk.client.JdkClientContainer;

/**
 * CLI entry point to Jenkins.
 */
@SuppressFBWarnings(value = "CRLF_INJECTION_LOGS", justification = "We don't care about this behavior")
public class CLI {

    private CLI() {}

    /**
     * Make sure the connection is open against Jenkins server.
     *
     * @param c The open connection.
     * @throws IOException in case of communication problem.
     * @throws NotTalkingToJenkinsException when connection is not made to Jenkins service.
     */
    /*package*/ static void verifyJenkinsConnection(URLConnection c) throws IOException {
        if (c.getHeaderField("X-Hudson") == null && c.getHeaderField("X-Jenkins") == null)
            throw new NotTalkingToJenkinsException(c);
    }

    /*package*/ static final class NotTalkingToJenkinsException extends IOException {
        NotTalkingToJenkinsException(String s) {
            super(s);
        }

        NotTalkingToJenkinsException(URLConnection c) {
            super("There's no Jenkins running at " + c.getURL().toString());
        }
    }

    public static void main(final String[] _args) throws Exception {
        try {
            System.exit(_main(_args));
        } catch (NotTalkingToJenkinsException ex) {
            LOGGER.log(Level.SEVERE, ex.getMessage(), ex);
            System.exit(3);
        } catch (Exception e) {
            // if the CLI main thread die, make sure to kill the JVM.
            e.printStackTrace();
            System.exit(-1);
        }
    }

    private enum Mode { HTTP, SSH, WEB_SOCKET }

    public static int _main(String[] _args) throws Exception {
        List<String> args = Arrays.asList(_args);
        PrivateKeyProvider provider = new PrivateKeyProvider();

        String url = System.getenv("JENKINS_URL");

        if (url == null)
            url = System.getenv("HUDSON_URL");

        boolean noKeyAuth = false;

        Mode mode = null;

        String user = null;
        String auth = null;
        String bearer = null;

        String userIdEnv = System.getenv("JENKINS_USER_ID");
        String tokenEnv = System.getenv("JENKINS_API_TOKEN");

        boolean strictHostKey = false;
        boolean noCertificateCheck = false;

        while (!args.isEmpty()) {
            String head = args.get(0);
            switch (head) {
                case "-version":
                    LOGGER.log(Level.INFO, "Version: " + computeVersion());
                    return 0;
                case "-http":
                    if (mode != null) {
                        printUsage("-http clashes with previously defined mode " + mode);
                        return -1;
                    }
                    mode = Mode.HTTP;
                    break;
                case "-ssh":
                    if (mode != null) {
                        printUsage("-ssh clashes with previously defined mode " + mode);
                        return -1;
                    }
                    mode = Mode.SSH;
                    break;
                case "-webSocket":
                    if (mode != null) {
                        printUsage("-webSocket clashes with previously defined mode " + mode);
                        return -1;
                    }
                    mode = Mode.WEB_SOCKET;
                    break;
                case "-remoting":
                    printUsage("-remoting mode is no longer supported");
                    return -1;
                case "-s":
                    if (args.size() >= 2) {
                        url = args.get(1);
                        args = args.subList(2, args.size());
                        continue;
                    }
                    break;
                case "-noCertificateCheck":
                    LOGGER.info("Skipping HTTPS certificate checks altogether. Note that this is not secure at all.");
                    noCertificateCheck = true;
                    break;
                case "-noKeyAuth":
                    noKeyAuth = true;
                    break;
                case "-i":
                    if (args.size() >= 2) {
                        File f = getFileFromArguments(args);
                        if (!f.exists()) {
                            printUsage(Messages.CLI_NoSuchFileExists(f));
                            return -1;
                        }

                        provider.readFrom(f);
                        args = args.subList(2, args.size());
                        continue;
                    }
                    break;
                case "-strictHostKey":
                    strictHostKey = true;
                    break;
                case "-user":
                    if (args.size() >= 2) {
                        user = args.get(1);
                        args = args.subList(2, args.size());
                        continue;
                    }
                    break;
                case "-auth":
                    if (args.size() >= 2) {
                        auth = args.get(1);
                        args = args.subList(2, args.size());
                        continue;
                    }
                    break;
                case "-bearer":
                    if (args.size() >= 2) {
                        bearer = args.get(1);
                        args = args.subList(2, args.size());
                        continue;
                    }
                    break;
                case "-logger":
                    if (args.size() >= 2) {
                        Level level = parse(args.get(1));
                        for (Handler h : Logger.getLogger("").getHandlers()) {
                            h.setLevel(level);
                        }
                        for (Logger logger : new Logger[] {LOGGER, FullDuplexHttpStream.LOGGER, PlainCLIProtocol.LOGGER, Logger.getLogger("org.apache.sshd")}) { // perhaps also Channel
                            logger.setLevel(level);
                        }
                        args = args.subList(2, args.size());
                        continue;
                    }
                    break;
                default:
                    break;
            }
            args = args.subList(1, args.size());
        }

        if (url == null) {
            printUsage(Messages.CLI_NoURL());
            return -1;
        }

        if (auth != null && bearer != null) {
            LOGGER.warning("-auth and -bearer are mutually exclusive");
        }

        if (auth == null && bearer == null) {
            // -auth option not set
            if ((userIdEnv != null && !userIdEnv.isBlank()) && (tokenEnv != null && !tokenEnv.isBlank())) {
                auth = userIdEnv.concat(":").concat(tokenEnv);
            } else if ((userIdEnv != null && !userIdEnv.isBlank()) || (tokenEnv != null && !tokenEnv.isBlank())) {
                printUsage(Messages.CLI_BadAuth());
                return -1;
            } // Otherwise, none credentials were set

        }

        if (!url.endsWith("/")) {
            url += '/';
        }

        if (args.isEmpty())
            args = List.of("help"); // default to help

        if (mode == null) {
            mode = Mode.WEB_SOCKET;
        }

        LOGGER.log(FINE, "using connection mode {0}", mode);

        if (user != null && auth != null) {
            LOGGER.warning("-user and -auth are mutually exclusive");
        }

        if (mode == Mode.SSH) {
            if (user == null) {
                // TODO SshCliAuthenticator already autodetects the user based on public key; why cannot AsynchronousCommand.getCurrentUser do the same?
                LOGGER.warning("-user required when using -ssh");
                return -1;
            }
            if (!noKeyAuth && !provider.hasKeys()) {
                provider.readFromDefaultLocations();
            }
            return SSHCLI.sshConnection(url, user, args, provider, strictHostKey);
        }

        if (strictHostKey) {
            LOGGER.warning("-strictHostKey meaningful only with -ssh");
        }

        if (noKeyAuth) {
            LOGGER.warning("-noKeyAuth meaningful only with -ssh");
        }

        if (user != null) {
            LOGGER.warning("Warning: -user ignored unless using -ssh");
        }

        CLIConnectionFactory factory = new CLIConnectionFactory().noCertificateCheck(noCertificateCheck);
        String userInfo = new URL(url).getUserInfo();
        if (userInfo != null) {
            factory = factory.basicAuth(userInfo);
        } else if (auth != null) {
            factory = factory.basicAuth(auth.startsWith("@") ? readAuthFromFile(auth).trim() : auth);
        } else if (bearer != null) {
            factory = factory.bearerAuth(bearer.startsWith("@") ? readAuthFromFile(bearer).trim() : bearer);
        }


        if (mode == Mode.HTTP) {
            return plainHttpConnection(url, args, factory);
        }

        if (mode == Mode.WEB_SOCKET) {
            return webSocketConnection(url, args, factory);
        }

        throw new AssertionError();
    }

    @SuppressFBWarnings(value = {"PATH_TRAVERSAL_IN", "URLCONNECTION_SSRF_FD"}, justification = "User provided values for running the program.")
    private static String readAuthFromFile(String auth) throws IOException {
        Path path;
        try {
            path = Paths.get(auth.substring(1));
        } catch (InvalidPathException e) {
            throw new IOException(e);
        }
        return Files.readString(path, Charset.defaultCharset());
    }

    @SuppressFBWarnings(value = {"PATH_TRAVERSAL_IN", "URLCONNECTION_SSRF_FD"}, justification = "User provided values for running the program.")
    private static File getFileFromArguments(List<String> args) {
        return new File(args.get(1));
    }

    private static int webSocketConnection(String url, List<String> args, CLIConnectionFactory factory) throws Exception {
        LOGGER.fine(() -> "Trying to connect to " + url + " via plain protocol over WebSocket");
        class CLIEndpoint extends Endpoint {
            @Override
            public void onOpen(Session session, EndpointConfig config) {
                // This method is intentionally left empty because we do not need to perform any actions
                // when the WebSocket connection is opened. The connection setup and message handling
                // are managed elsewhere in the code.
            }
        }

        class Authenticator extends ClientEndpointConfig.Configurator {
            HandshakeResponse hr;
            @Override
            public void beforeRequest(Map<String, List<String>> headers) {
                if (factory.authorization != null) {
                    headers.put("Authorization", List.of(factory.authorization));
                }
            }
            @Override
            public void afterResponse(HandshakeResponse hr) {
                this.hr = hr;
            }
        }
        var authenticator = new Authenticator();

        ClientManager client = ClientManager.createClient(JdkClientContainer.class.getName()); // ~ ContainerProvider.getWebSocketContainer()
        client.getProperties().put(ClientProperties.REDIRECT_ENABLED, true); // https://tyrus-project.github.io/documentation/1.13.1/index/tyrus-proprietary-config.html#d0e1775
        if (factory.noCertificateCheck) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] {new NoCheckTrustManager()}, new SecureRandom());
            SslEngineConfigurator sslEngineConfigurator = new SslEngineConfigurator(sslContext);
            sslEngineConfigurator.setHostnameVerifier((s, sslSession) -> true);
            client.getProperties().put(ClientProperties.SSL_ENGINE_CONFIGURATOR, sslEngineConfigurator);
        }
        Session session;
        try {
            session = client.connectToServer(new CLIEndpoint(), ClientEndpointConfig.Builder.create().configurator(authenticator).build(), URI.create(url.replaceFirst("^http", "ws") + "cli/ws"));
        } catch (DeploymentHandshakeException x) {
            LOGGER.severe("CLI handshake failed with status code " + x.getHttpStatusCode());
            if (authenticator.hr != null) {
                for (var entry : authenticator.hr.getHeaders().entrySet()) {
                    // org.glassfish.tyrus.core.Utils.parseHeaderValue improperly splits values like Date at commas, so undo that:
                    LOGGER.severe(entry.getKey() + ": " + String.join(", ", entry.getValue()));
                }
                // UpgradeResponse.getReasonPhrase is useless since Jetty generates it from the code,
                // and the body is not accessible at all.
            }
            return 15; // compare CLICommand.main
        }
        PlainCLIProtocol.Output out = new PlainCLIProtocol.Output() {
            @Override
            public void send(byte[] data) throws IOException {
                session.getBasicRemote().sendBinary(ByteBuffer.wrap(data));
            }

            @Override
            public void close() throws IOException {
                session.close();
            }
        };
        try (ClientSideImpl connection = new ClientSideImpl(out)) {
            session.addMessageHandler(InputStream.class, is -> {
                try {
                    connection.handle(new DataInputStream(is));
                } catch (IOException x) {
                    LOGGER.log(Level.WARNING, null, x);
                }
            });
            connection.start(args);
            return connection.exit();
        }
    }

    private static int plainHttpConnection(String url, List<String> args, CLIConnectionFactory factory)
            throws GeneralSecurityException, IOException, InterruptedException {
        LOGGER.log(FINE, "Trying to connect to {0} via plain protocol over HTTP", url);
        if (factory.noCertificateCheck) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] {new NoCheckTrustManager()}, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> {
                HostnameVerifier defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
                return defaultVerifier.verify(hostname, session);
            });
        }
        FullDuplexHttpStream streams = new FullDuplexHttpStream(new URL(url), "cli?remoting=false", factory.authorization);
        try (ClientSideImpl connection = new ClientSideImpl(new PlainCLIProtocol.FramedOutput(streams.getOutputStream()))) {
            connection.start(args);
            InputStream is = streams.getInputStream();
            if (is.read() != 0) { // cf. FullDuplexHttpService
                throw new IOException("expected to see initial zero byte; perhaps you are connecting to an old server which does not support -http?");
            }
            new PlainCLIProtocol.FramedReader(connection, is).start();
            new Thread("ping") { // JENKINS-46659
                @Override
                public void run() {
                    try {
                        Thread.sleep(PING_INTERVAL);
                        while (!connection.complete) {
                            LOGGER.fine("sending ping");
                            connection.sendEncoding(Charset.defaultCharset().name()); // no-op at this point
                            Thread.sleep(PING_INTERVAL);
                        }
                    } catch (IOException x) {
                        LOGGER.log(Level.WARNING, null, x);
                    } catch (InterruptedException x) {
                        Thread.currentThread().interrupt();
                        LOGGER.log(Level.WARNING, null, x);
                    }
                }

            }.start();
            return connection.exit();
        }
    }

    private static final class ClientSideImpl extends PlainCLIProtocol.ClientSide {

        volatile boolean complete;
        private int exit = -1;

        ClientSideImpl(PlainCLIProtocol.Output out) {
            super(out);
        }

        void start(List<String> args) throws IOException {
            for (String arg : args) {
                sendArg(arg);
            }
            sendEncoding(Charset.defaultCharset().name());
            sendLocale(Locale.getDefault().toString());
            sendStart();
            new Thread("input reader") {
                @Override
                public void run() {
                    try {
                        final OutputStream stdin = streamStdin();
                        byte[] buf = new byte[60_000]; // less than 64Kb frame size for WS
                        while (!complete) {
                            int len = System.in.read(buf);
                            if (len == -1) {
                                break;
                            } else {
                                stdin.write(buf, 0, len);
                            }
                        }
                        sendEndStdin();
                    } catch (IOException x) {
                        LOGGER.log(Level.WARNING, null, x);
                    }
                }
            }.start();
        }

        @Override
        protected synchronized void onExit(int code) {
            this.exit = code;
            finished();
        }

        @Override
        protected void onStdout(InputStream chunk) throws IOException {
            IOUtils.copy(chunk, System.out);
        }

        protected void onStderr(byte[] chunk) throws IOException {
            LOGGER.log(Level.SEVERE, new String(chunk));
        }

        @Override
        protected void handleClose() {
            finished();
        }

        private synchronized void finished() {
            complete = true;
            notifyAll();
        }

        synchronized int exit() throws InterruptedException {
            while (!complete) {
                wait();
            }
            return exit;
        }

    }

    private static String computeVersion() {
        Properties props = new Properties();
        try (InputStream is = CLI.class.getResourceAsStream("/jenkins/cli/jenkins-cli-version.properties")) {
            if (is != null) {
                props.load(is);
            }
        } catch (IOException e) {
            e.printStackTrace(); // if the version properties is missing, that's OK.
        }
        return props.getProperty("version", "?");
    }

    /**
     * Loads RSA/DSA private key in a PEM format into {@link KeyPair}.
     */
    public static KeyPair loadKey(File f, String passwd) throws IOException, GeneralSecurityException {
        return PrivateKeyProvider.loadKey(f, passwd);
    }

    public static KeyPair loadKey(File f) throws IOException, GeneralSecurityException {
        return loadKey(f, null);
    }

    /**
     * Loads RSA/DSA private key in a PEM format into {@link KeyPair}.
     */
    public static KeyPair loadKey(String pemString, String passwd) throws IOException, GeneralSecurityException {
        return PrivateKeyProvider.loadKey(pemString, passwd);
    }

    public static KeyPair loadKey(String pemString) throws IOException, GeneralSecurityException {
        return loadKey(pemString, null);
    }

    /** For access from {@code HelpCommand}. */
    static String usage() {
        return Messages.CLI_Usage();
    }

    private static void printUsage(String msg) {
        if (msg != null)   System.out.println(msg);
        LOGGER.severe(usage());
    }

    static final Logger LOGGER = Logger.getLogger(CLI.class.getName());

    private static final int PING_INTERVAL = Integer.getInteger(CLI.class.getName() + ".pingInterval", 3_000); // JENKINS-59267
}
