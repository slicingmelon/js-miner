package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.*;
import burp.api.montoya.ui.menu.Menu;
import burp.api.montoya.ui.menu.MenuItem;
import burp.config.ExecutorServiceManager;
import burp.config.ExtensionConfig;
import burp.core.TaskRepository;
import burp.core.ScannerBuilder;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static burp.utils.Constants.SETTING_BURP_PASSIVE;
import static burp.utils.Constants.SETTING_VERBOSE_LOGGING;

public class BurpExtender implements BurpExtension {
    private final MontoyaApi api;
    private static final ExecutorServiceManager executorServiceManager = ExecutorServiceManager.getInstance();
    private static final TaskRepository taskRepository = TaskRepository.getInstance();
    private static final ExtensionConfig extensionConfig = ExtensionConfig.getInstance();
    public static final String EXTENSION_NAME = "JS Miner-NG";
    private static final String EXTENSION_VERSION = "2.0";
    private int taskCount = 0;

    public BurpExtender(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);
        
        // Initialize components
        TaskRepository.setApi(api);
        
        // Register unloading handler
        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                taskRepository.destroy();
                api.logging().logToOutput("Sending shutdown signal to terminate any running threads...");
                executorServiceManager.getExecutorService().shutdownNow();
                api.logging().logToOutput("Extension was unloaded");
                api.logging().logToOutput("=================================================");
            }
        });
        
        // Register context menu
        api.userInterface().registerContextMenuItemsProvider(this::createMenuItems);
        
        // Register HTTP handler for passive scanning
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                if (extensionConfig.isPassiveEnabled()) {
                    doPassiveScan(responseReceived);
                }
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        api.logging().logToOutput("Loading " + EXTENSION_NAME + " v" + EXTENSION_VERSION);
        api.logging().logToOutput("Original Author: Mina M. Edwar");
        api.logging().logToOutput("Forked by: pedro (slicingmelon)");
        
        loadExtensionConfig();
    }

    private List<MenuItem> createMenuItems(ContextMenuEvent event) {
        if (!event.messageEditorRequestResponse().isPresent() && 
            !event.selectedRequestResponses().isEmpty()) {
            
            List<MenuItem> menuItems = new ArrayList<>();
            List<HttpRequestResponse> selectedMessages = event.selectedRequestResponses();
            
            // Main menu item
            menuItems.add(MenuItem.builder()
                .text("Run JS Auto-Mine (check everything)")
                .action(e -> runAutoMine(selectedMessages))
                .build());
            
            // Add submenus
            menuItems.add(Menu.builder()
                .text("Scans")
                .menuItems(createScanMenuItems(selectedMessages))
                .build());
                
            menuItems.add(Menu.builder()
                .text("Config")
                .menuItems(createConfigMenuItems())
                .build());
                
            menuItems.add(Menu.builder()
                .text("Log")
                .menuItems(createLogMenuItems())
                .build());
                
            return menuItems;
        }
        return List.of();
    }

    private void runAutoMine(List<HttpRequestResponse> messages) {
        new Thread(() -> {
            long ts = Instant.now().toEpochMilli();
            ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(api, messages.toArray(new HttpRequestResponse[0]))
                .runAllPassiveScans()
                .taskId(++taskCount)
                .timeStamp(ts)
                .build();
            scannerBuilder.runScans();
        }).start();
    }

    private void doPassiveScan(HttpResponseReceived response) {
        new Thread(() -> {
            long ts = Instant.now().toEpochMilli();
            ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(api)
                .withHttpResponse(response)
                .runAllPassiveScans()
                .timeStamp(ts)
                .build();
            scannerBuilder.runScans();
        }).start();
    }

    private List<MenuItem> createScanMenuItems(List<HttpRequestResponse> messages) {
        List<MenuItem> menuItems = new ArrayList<>();
        
        // All passive scans
        addScanMenuItem(menuItems, "Run all passive scans", messages, 
            b -> b.runAllPassiveScans().timeStamp(Instant.now().toEpochMilli()));
            
        // Source Mapper
        addScanMenuItem(menuItems, "JS source mapper (active)", messages, 
            ScannerBuilder.Builder::scanSourceMapper);
            
        // Add other scan items
        addScanMenuItem(menuItems, "Secrets", messages, ScannerBuilder.Builder::scanSecrets);
        addScanMenuItem(menuItems, "Dependency Confusion", messages, ScannerBuilder.Builder::scanDependencyConfusion);
        addScanMenuItem(menuItems, "SubDomains", messages, ScannerBuilder.Builder::scanSubdomains);
        addScanMenuItem(menuItems, "Cloud URLs", messages, ScannerBuilder.Builder::scanCloudURLs);
        addScanMenuItem(menuItems, "Inline B64 JS Source Maps", messages, 
            b -> b.scanSourceMapper().timeStamp(Instant.now().toEpochMilli()));
        addScanMenuItem(menuItems, "Dump Static Files", messages, 
            b -> b.dumpStaticFiles().timeStamp(Instant.now().toEpochMilli()));
        addScanMenuItem(menuItems, "API Endpoints Finder", messages, ScannerBuilder.Builder::scanEndpoints);
        
        return menuItems;
    }

    private void addScanMenuItem(List<MenuItem> menuItems, String text, List<HttpRequestResponse> messages, 
            Function<ScannerBuilder.Builder, ScannerBuilder.Builder> scanType) {
        menuItems.add(MenuItem.builder()
            .text(text)
            .action(e -> runScan(messages, scanType))
            .build());
    }

    private void runScan(List<HttpRequestResponse> messages, 
            Function<ScannerBuilder.Builder, ScannerBuilder.Builder> scanType) {
        new Thread(() -> {
            ScannerBuilder scannerBuilder = scanType.apply(new ScannerBuilder.Builder(api, messages.toArray(new HttpRequestResponse[0])))
                .taskId(++taskCount)
                .build();
            scannerBuilder.runScans();
        }).start();
    }

    private void updateExtensionConfig() {
        api.persistence().preferences().setString(SETTING_VERBOSE_LOGGING, 
            String.valueOf(extensionConfig.isVerboseLogging()));
        api.persistence().preferences().setString(SETTING_BURP_PASSIVE, 
            String.valueOf(extensionConfig.isPassiveEnabled()));
    }

    private void loadExtensionConfig() {
        String verboseLogging = api.persistence().preferences().getString(SETTING_VERBOSE_LOGGING);
        if (verboseLogging != null) {
            extensionConfig.setVerboseLogging(Boolean.parseBoolean(verboseLogging));
        }

        String passiveEnabled = api.persistence().preferences().getString(SETTING_BURP_PASSIVE);
        if (passiveEnabled != null) {
            extensionConfig.setPassiveEnabled(Boolean.parseBoolean(passiveEnabled));
        }
    }
}