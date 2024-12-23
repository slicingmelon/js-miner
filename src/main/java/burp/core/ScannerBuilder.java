package burp.core;

import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.core.scanners.*;
import burp.utils.Utilities;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import static burp.utils.Constants.*;


/**
 * Class to build and run specific scans. It also feeds data to TaskRepository.
 */
public class ScannerBuilder {
    private static final String[] EXTENSION_JS = {"js"};
    private static final String[] EXTENSION_JS_JSON = {"js", "json"};
    private static final String[] EXTENSION_CSS = {"css"};
    private static final String[] EXTENSION_JS_JSON_CSS_MAP = {"js", "json", "css", "map"};

    private final HttpRequestResponse[] requestResponses;
    private final int taskId;
    private final long timeStamp;
    private boolean scanSecrets;
    private boolean scanDependencyConfusion;
    private boolean scanEndpoints;
    private boolean scanSourceMapper;
    private boolean dumpStaticFiles;
    private boolean runAllPassiveScans;

    public static class Builder {
        private final HttpRequestResponse[] requestResponses;
        private long timeStamp = Instant.now().toEpochMilli();
        private int taskId = -1;
        private boolean scanSecrets = false;
        private boolean scanDependencyConfusion = false;
        private boolean scanEndpoints = false;
        private boolean scanSourceMapper = false;
        private boolean dumpStaticFiles = false;
        private boolean runAllPassiveScans = false;

        public Builder(HttpRequestResponse[] requestResponses) {
            this.requestResponses = requestResponses;
        }

        public Builder taskId(int id) {
            taskId = id;
            return this;
        }

        public Builder scanSecrets() {
            scanSecrets = true;
            return this;
        }

        public Builder scanDependencyConfusion() {
            scanDependencyConfusion = true;
            return this;
        }

        public Builder scanEndpoints() {
            scanEndpoints = true;
            return this;
        }

        public Builder scanSourceMapper() {
            scanSourceMapper = true;
            return this;
        }

        public Builder timeStamp(long ts) {
            timeStamp = ts;
            return this;
        }

        public Builder dumpStaticFiles() {
            dumpStaticFiles = true;
            return this;
        }

        public Builder runAllPassiveScans() {
            scanDependencyConfusion = true;
            scanEndpoints = true;
            scanSecrets = true;
            scanSourceMapper = true;
            runAllPassiveScans = true;
            return this;
        }

        public ScannerBuilder build() {
            return new ScannerBuilder(this);
        }
    }

    private ScannerBuilder(Builder builder) {
        this.requestResponses = builder.requestResponses;
        this.taskId = builder.taskId;
        this.timeStamp = builder.timeStamp;
        this.scanSecrets = builder.scanSecrets;
        this.scanDependencyConfusion = builder.scanDependencyConfusion;
        this.scanEndpoints = builder.scanEndpoints;
        this.scanSourceMapper = builder.scanSourceMapper;
        this.dumpStaticFiles = builder.dumpStaticFiles;
        this.runAllPassiveScans = builder.runAllPassiveScans;
    }

    public void runScans() {
        if (scanSecrets || runAllPassiveScans) {
            runSecretsScan(requestResponses, taskId, timeStamp);
        }

        if (scanDependencyConfusion) {
            runDependencyConfusionScan(requestResponses, taskId, timeStamp);
        }

        if (scanEndpoints) {
            runEndpointsScan(requestResponses, taskId, timeStamp);
        }

        if (scanSourceMapper) {
            runSourceMapperScan(requestResponses, taskId, timeStamp);
        }

        if (dumpStaticFiles) {
            runStaticFilesDumper(requestResponses, taskId, timeStamp);
        }
    }

    private static void scanVerifierExecutor(HttpRequestResponse requestResponse, int taskId, TaskName taskName, long timeStamp, boolean isLastIterator) {
        String url = requestResponse.request().url();
        byte[] responseBodyHash = Utilities.getHTTPResponseBodyHash(requestResponse);
        
        if (BurpExtender.getTaskRepository().notDuplicate(taskName, url, responseBodyHash)) {
            UUID uuid = UUID.randomUUID();
            BurpExtender.getTaskRepository().addTask(
                    new Task(taskId, uuid, taskName, url, responseBodyHash)
            );
            
            switch (taskName) {
                case SECRETS_SCAN:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new Secrets(requestResponse, uuid));
                    break;
                case DEPENDENCY_CONFUSION_SCAN:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new DependencyConfusion(requestResponse, uuid, true));
                    break;
                case DEPENDENCY_CONFUSION_SCAN_2:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new DependencyConfusion(requestResponse, uuid, false));
                    break;
                case ENDPOINTS_FINDER:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new Endpoints(requestResponse, uuid));
                    break;
                case SUBDOMAINS_SCAN:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new SubDomains(requestResponse, uuid));
                    break;
                case CLOUD_URLS_SCAN:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new CloudURLs(requestResponse, uuid));
                    break;
                case INLINE_JS_SOURCE_MAPPER:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new InlineSourceMapFiles(requestResponse, uuid, timeStamp));
                    break;
                case SOURCE_MAPPER_ACTIVE_SCAN:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new ActiveSourceMapper(requestResponse, timeStamp, uuid));
                    break;
                case STATIC_FILES_DUMPER:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new StaticFilesDumper(requestResponse, timeStamp, uuid, isLastIterator));
                    break;
                default:
                    break;
            }
        } else {
            logSkippedScanInfo(taskId, taskName, url);
        }
    }

    private static void runSecretsScan(HttpRequestResponse[] requestResponses, int taskId, long timeStamp) {
        Set<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(requestResponses, EXTENSION_JS_JSON);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.SECRETS_SCAN, timeStamp, false);
        }
    }

    private static void runDependencyConfusionScan(HttpRequestResponse[] requestResponses, int taskId, long timeStamp) {
        Set<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(requestResponses, EXTENSION_JS_JSON);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.DEPENDENCY_CONFUSION_SCAN, timeStamp, false);
        }

        Set<HttpRequestResponse> uniqueRequestsCSS = Utilities.querySiteMap(requestResponses, EXTENSION_CSS);
        for (HttpRequestResponse requestResponse : uniqueRequestsCSS) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.DEPENDENCY_CONFUSION_SCAN_2, timeStamp, false);
        }
    }

    private static void runEndpointsScan(HttpRequestResponse[] requestResponses, int taskId, long timeStamp) {
        Set<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(requestResponses, EXTENSION_JS);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.ENDPOINTS_FINDER, timeStamp, false);
        }
    }

    private static void runSourceMapperScan(HttpRequestResponse[] requestResponses, int taskId, long timeStamp) {
        Set<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(requestResponses, EXTENSION_JS);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.SOURCE_MAPPER_ACTIVE_SCAN, timeStamp, false);
        }
    }

    private static void runStaticFilesDumper(HttpRequestResponse[] requestResponses, int taskId, long timeStamp) {
        Set<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(requestResponses, EXTENSION_JS_JSON_CSS_MAP);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.STATIC_FILES_DUMPER, timeStamp, false);
        }
    }

    @Override
    public String toString() {
        return "Scan Information{" +
                "RequestURL=" + Utilities.getURLPrefix(requestResponses[0]) +
                ", taskId=" + taskId +
                ", timeStamp=" + timeStamp +
                ", scanSecrets=" + scanSecrets +
                ", scanDependencyConfusion=" + scanDependencyConfusion +
                ", scanEndpoints=" + scanEndpoints +
                ", scanSourceMapper=" + scanSourceMapper +
                ", dumpStaticFiles=" + dumpStaticFiles +
                '}';
    }

    private static void logSkippedScanInfo(int taskId, TaskName taskName, String url) {
        if (BurpExtender.getExtensionConfig().isVerboseLogging()) {
            BurpExtender.api.logging().logToOutput(String.format(LOG_FORMAT,
                    "Skipped",
                    taskName,
                    url,
                    LOG_TASK_ID_PREFIX + taskId));
        }
    }

}
