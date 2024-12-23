package burp.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.core.scanners.*;
import burp.utils.Utilities;
import burp.config.ExtensionConfig;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static burp.utils.Constants.*;


/**
 * Class to build and run specific scans. It also feeds data to TaskRepository.
 */
public class ScannerBuilder {
    private static final String[] EXTENSION_JS = {"js"};
    private static final String[] EXTENSION_JS_JSON = {"js", "json"};
    private static final String[] EXTENSION_CSS = {"css"};
    private static final String[] EXTENSION_JS_JSON_CSS_MAP = {"js", "json", "css", "map"};

    private static final String LOG_FORMAT = "[%s] %s | %s | %s";
    private static final String LOG_TASK_ID_PREFIX = "Task ID: ";

    private final HttpRequestResponse[] requestResponses;
    private final int taskId;
    private final long timeStamp;
    private final MontoyaApi api;
    private boolean scanSecrets;
    private boolean scanDependencyConfusion;
    private boolean scanEndpoints;
    private boolean scanSourceMapper;
    private boolean scanSubdomains;
    private boolean scanCloudURLs;
    private boolean dumpStaticFiles;
    private boolean runAllPassiveScans;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);

    public static class Builder {
        private HttpRequestResponse[] requestResponses;
        private final MontoyaApi api;
        private long timeStamp = Instant.now().toEpochMilli();
        private int taskId = -1;
        private boolean scanSecrets = false;
        private boolean scanDependencyConfusion = false;
        private boolean scanEndpoints = false;
        private boolean scanSourceMapper = false;
        private boolean scanSubdomains = false;
        private boolean scanCloudURLs = false;
        private boolean dumpStaticFiles = false;
        private boolean runAllPassiveScans = false;

        public Builder(MontoyaApi api, HttpRequestResponse[] requestResponses) {
            this.api = api;
            this.requestResponses = requestResponses;
        }

        public Builder(MontoyaApi api) {
            this.api = api;
            this.requestResponses = new HttpRequestResponse[0];
        }

        public Builder withHttpResponse(HttpResponseReceived response) {
            HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                response.initiatingRequest(),
                response
            );
            this.requestResponses = new HttpRequestResponse[]{requestResponse};
            return this;
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

        public Builder scanSubdomains() {
            scanSubdomains = true;
            return this;
        }

        public Builder scanCloudURLs() {
            scanCloudURLs = true;
            return this;
        }

        public Builder runAllPassiveScans() {
            scanDependencyConfusion = true;
            scanEndpoints = true;
            scanSecrets = true;
            scanSourceMapper = true;
            scanSubdomains = true;
            scanCloudURLs = true;
            runAllPassiveScans = true;
            return this;
        }

        public ScannerBuilder build() {
            return new ScannerBuilder(this);
        }
    }

    private ScannerBuilder(Builder builder) {
        this.api = builder.api;
        this.requestResponses = builder.requestResponses;
        this.taskId = builder.taskId;
        this.timeStamp = builder.timeStamp;
        this.scanSecrets = builder.scanSecrets;
        this.scanDependencyConfusion = builder.scanDependencyConfusion;
        this.scanEndpoints = builder.scanEndpoints;
        this.scanSourceMapper = builder.scanSourceMapper;
        this.scanSubdomains = builder.scanSubdomains;
        this.scanCloudURLs = builder.scanCloudURLs;
        this.dumpStaticFiles = builder.dumpStaticFiles;
        this.runAllPassiveScans = builder.runAllPassiveScans;
    }

    public boolean isRunning() {
        return isRunning.get();
    }

    public void runScans() {
        if (!isRunning.compareAndSet(false, true)) {
            api.logging().logToOutput("A scan is already running");
            return;
        }
        
        try {
            if (scanSecrets || runAllPassiveScans) {
                runSecretsScan();
            }

            if (scanDependencyConfusion) {
                runDependencyConfusionScan();
            }

            if (scanEndpoints) {
                runEndpointsScan();
            }

            if (scanSourceMapper) {
                runSourceMapperScan();
            }

            if (dumpStaticFiles) {
                runStaticFilesDumper();
            }

            if (scanSubdomains || runAllPassiveScans) {
                runSubdomainsScan();
            }

            if (scanCloudURLs || runAllPassiveScans) {
                runCloudURLsScan();
            }
        } finally {
            isRunning.set(false);
        }
    }

    private void scanVerifierExecutor(HttpRequestResponse requestResponse, TaskName taskName, boolean isLastIterator) {
        String url = requestResponse.request().url();
        byte[] responseBodyHash = Utilities.getHTTPResponseBodyHash(requestResponse);
        TaskRepository taskRepository = TaskRepository.getInstance();
        
        if (taskRepository.notDuplicate(taskName, url, responseBodyHash)) {
            UUID uuid = UUID.randomUUID();
            taskRepository.addTask(new Task(taskId, uuid, taskName, url, responseBodyHash));
            
            Runnable scanner = switch (taskName) {
                case SECRETS_SCAN -> new Secrets(api, requestResponse, uuid);
                case DEPENDENCY_CONFUSION_SCAN -> new DependencyConfusion(api, requestResponse, uuid, true);
                case DEPENDENCY_CONFUSION_SCAN_2 -> new DependencyConfusion(api, requestResponse, uuid, false);
                case ENDPOINTS_FINDER -> new Endpoints(api, requestResponse, uuid);
                case SUBDOMAINS_SCAN -> new SubDomains(api, requestResponse, uuid);
                case CLOUD_URLS_SCAN -> new CloudURLs(api, requestResponse, uuid);
                case INLINE_JS_SOURCE_MAPPER -> new InlineSourceMapFiles(api, requestResponse, uuid, timeStamp);
                case SOURCE_MAPPER_ACTIVE_SCAN -> new ActiveSourceMapper(api, requestResponse, timeStamp, uuid);
                case STATIC_FILES_DUMPER -> new StaticFilesDumper(api, requestResponse, timeStamp, uuid, isLastIterator);
                default -> null;
            };

            if (scanner != null) {
                scanner.run();
            }
        } else {
            logSkippedScanInfo(taskName, url);
        }
    }

    private void runSecretsScan() {
        Set<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(requestResponses, EXTENSION_JS_JSON);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, TaskName.SECRETS_SCAN, false);
        }
    }

    private void runDependencyConfusionScan() {
        Set<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(requestResponses, EXTENSION_JS_JSON);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, TaskName.DEPENDENCY_CONFUSION_SCAN, false);
        }

        Set<HttpRequestResponse> uniqueRequestsCSS = Utilities.querySiteMap(requestResponses, EXTENSION_CSS);
        for (HttpRequestResponse requestResponse : uniqueRequestsCSS) {
            scanVerifierExecutor(requestResponse, TaskName.DEPENDENCY_CONFUSION_SCAN_2, false);
        }
    }

    private void runEndpointsScan() {
        Set<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(requestResponses, EXTENSION_JS);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, TaskName.ENDPOINTS_FINDER, false);
        }
    }

    private void runSourceMapperScan() {
        Set<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(requestResponses, EXTENSION_JS);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, TaskName.SOURCE_MAPPER_ACTIVE_SCAN, false);
        }
    }

    private void runStaticFilesDumper() {
        Set<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(requestResponses, EXTENSION_JS_JSON_CSS_MAP);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, TaskName.STATIC_FILES_DUMPER, false);
        }
    }

    private void runSubdomainsScan() {
        Set<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(requestResponses, EXTENSION_JS);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, TaskName.SUBDOMAINS_SCAN, false);
        }
    }

    private void runCloudURLsScan() {
        Set<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(requestResponses, EXTENSION_JS);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, TaskName.CLOUD_URLS_SCAN, false);
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

    private void logSkippedScanInfo(TaskName taskName, String url) {
        if (ExtensionConfig.getInstance().isVerboseLogging()) {
            api.logging().logToOutput(String.format(LOG_FORMAT,
                    "Skipped",
                    LOG_TASK_ID_PREFIX + taskId,
                    taskName,
                    url));
        }
    }

}
