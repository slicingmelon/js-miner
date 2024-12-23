package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.*;
import burp.config.ExecutorServiceManager;
import burp.config.ExtensionConfig;
import burp.core.TaskRepository;
import burp.core.ScannerBuilder;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static burp.utils.Constants.SETTING_BURP_PASSIVE;
import static burp.utils.Constants.SETTING_VERBOSE_LOGGING;

public class BurpExtender implements BurpExtension {
    private static MontoyaApi api;
    private final ExecutorServiceManager executorServiceManager = ExecutorServiceManager.getInstance();
    private final TaskRepository taskRepository = TaskRepository.getInstance();
    private final ExtensionConfig extensionConfig = ExtensionConfig.getInstance();
    private static final String EXTENSION_NAME = "JS Miner-NG";
    private static final String EXTENSION_VERSION = "2.0";
    private int taskCount = 0;

    public static MontoyaApi getApi() {
        return api;
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(EXTENSION_NAME);
        
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

        // Log extension load
        api.logging().logToOutput("[*] Loaded:\t" + EXTENSION_NAME + " v" + EXTENSION_VERSION);
        api.logging().logToOutput("[*] Original Author:\tMina M. Edwar (minamo7sen@gmail.com)");
        api.logging().logToOutput("[*] Forked by:\tpedro (slicingmelon)");
        api.logging().logToOutput("=================================================");

        loadExtensionConfig();
    }

    private List<MenuItem> createMenuItems(ContextMenuEvent event) {
        List<MenuItem> menuItems = new ArrayList<>();
        
        if (!event.messageEditorRequestResponse().isPresent() && 
            !event.selectedRequestResponses().isEmpty()) {
            
            List<HttpRequestResponse> selectedMessages = event.selectedRequestResponses();
            
            // Main menu
            menuItems.add(MenuItem.builder()
                .text("Run JS Auto-Mine (check everything)")
                .action(e -> runAutoMine(selectedMessages))
                .build());
                
            // Scans submenu
            Menu scanMenu = Menu.builder()
                .text("Scans")
                .menuItems(createScanMenuItems(selectedMessages))
                .build();
            menuItems.add(scanMenu);
            
            // Config submenu
            Menu configMenu = Menu.builder()
                .text("Config")
                .menuItems(createConfigMenuItems())
                .build();
            menuItems.add(configMenu);
            
            // Log submenu
            Menu logMenu = Menu.builder()
                .text("Log")
                .menuItems(createLogMenuItems())
                .build();
            menuItems.add(logMenu);
        }
        
        return menuItems;
    }

    private void runAutoMine(List<HttpRequestResponse> messages) {
        new Thread(() -> {
            long ts = Instant.now().toEpochMilli();
            ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(messages.toArray(new HttpRequestResponse[0]))
                .runAllPassiveScans()
                .taskId(++taskCount)
                .timeStamp(ts)
                .build();
            scannerBuilder.runScans();
        }).start();
    }

    private void doPassiveScan(HttpResponseReceived response) {
        new Thread(() -> {
            ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(response)
                    .runAllPassiveScans()
                    .timeStamp(Instant.now().toEpochMilli())
                    .build();
            scannerBuilder.runScans();
        }).start();
    }

    private void updateExtensionConfig() {
        api.extension().saveSetting(SETTING_VERBOSE_LOGGING, String.valueOf(extensionConfig.isVerboseLogging()));
        api.extension().saveSetting(SETTING_BURP_PASSIVE, String.valueOf(extensionConfig.isPassiveEnabled()));
    }

    public void loadExtensionConfig() {
        if (api.extension().loadSetting(SETTING_VERBOSE_LOGGING) != null) {
            extensionConfig.setVerboseLogging(Boolean.parseBoolean(api.extension().loadSetting(SETTING_VERBOSE_LOGGING)));
        }

        if (api.extension().loadSetting(SETTING_BURP_PASSIVE) != null) {
            extensionConfig.setPassiveEnabled(Boolean.parseBoolean(api.extension().loadSetting(SETTING_BURP_PASSIVE)));
        }

    }

    @Override
    public void extensionUnloaded() {
        setLoaded(false);
        taskRepository.destroy();
        api.logging().logToOutput("[*] Sending shutdown signal to terminate any running threads..");
        executorServiceManager.getExecutorService().shutdownNow();
        api.logging().logToOutput("[*] Extension was unloaded.");
        api.logging().logToOutput("=================================================");
    }

    /*
     *  Context menu items
     */
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();
        JMenu scanItems = new JMenu("Scans");
        JMenu logItems = new JMenu("Log");
        JMenu configItems = new JMenu("Config");

        if (IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_PROXY_HISTORY == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE == invocation.getInvocationContext()
        ) {
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

            // === Main Scans Menu Items ==== //
            JMenuItem autoMineItem = new JMenuItem("Run JS Auto-Mine (check everything)");
            JSAutoMineItemAction autoMineItemActionAction = new JSAutoMineItemAction(selectedMessages);
            autoMineItem.addActionListener(autoMineItemActionAction);
            items.add(autoMineItem);

            JMenuItem findInterestingStuffItem = new JMenuItem("Run all passive scans ");
            AllPassiveScansItemAction findStuffAction = new AllPassiveScansItemAction(selectedMessages);
            findInterestingStuffItem.addActionListener(findStuffAction);
            items.add(findInterestingStuffItem);

            // === Specific Scans Menu Items ==== //
            JMenuItem jsSourceMapItem = new JMenuItem("JS source mapper (active)");
            ActiveSourceMapsItemAction jsMapAction = new ActiveSourceMapsItemAction(selectedMessages);
            jsSourceMapItem.addActionListener(jsMapAction);
            scanItems.add(jsSourceMapItem);

            JMenuItem secretsMenuItem = new JMenuItem("Secrets");
            secretsMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .scanSecrets()
                            .taskId(++taskCount)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(secretsMenuItem);

            JMenuItem dependencyConfusionMenuItem = new JMenuItem("Dependency Confusion");
            dependencyConfusionMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .scanDependencyConfusion()
                            .taskId(++taskCount)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(dependencyConfusionMenuItem);

            JMenuItem subDomainsMenuItem = new JMenuItem("SubDomains");
            subDomainsMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .scanSubDomains()
                            .taskId(++taskCount)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(subDomainsMenuItem);

            JMenuItem cloudURLsMenuItem = new JMenuItem("Cloud URLs");
            cloudURLsMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .scanCloudURLs()
                            .taskId(++taskCount)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(cloudURLsMenuItem);

            JMenuItem inlineSourceMapsMenuItem = new JMenuItem("Inline B64 JS Source Maps");
            inlineSourceMapsMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    long ts = Instant.now().toEpochMilli();
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .scanInlineSourceMapFiles()
                            .taskId(++taskCount)
                            .timeStamp(ts)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(inlineSourceMapsMenuItem);

            JMenuItem dumpStaticFilesMenuItem = new JMenuItem("Dump Static Files");
            dumpStaticFilesMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    long ts = Instant.now().toEpochMilli();
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .dumpStaticFiles()
                            .taskId(++taskCount)
                            .timeStamp(ts)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(dumpStaticFilesMenuItem);

            JMenuItem endpointsFinderMenuItem = new JMenuItem("API Endpoints Finder");
            endpointsFinderMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .endpointsFinder()
                            .taskId(++taskCount)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(endpointsFinderMenuItem);

            // === Logging Menu Items ==== //
            JMenuItem checkTasksMenuItem = new JMenuItem("Tasks Summary");
            checkTasksMenuItem.addActionListener(e -> {
                api.logging().logToOutput("[=============== Tasks Summary =============]");
                api.logging().logToOutput("Total Tasks: " + taskRepository.getSize());
                api.logging().logToOutput("Queued tasks: " + taskRepository.getQueuedTasks().size());
                api.logging().logToOutput("Completed tasks: " + taskRepository.getCompletedTasks().size());
                api.logging().logToOutput("Running tasks: " + taskRepository.getRunningTasks().size());
                api.logging().logToOutput("Failed tasks: " + taskRepository.getFailedTasks().size());
                api.logging().logToOutput("============================================");
            });
            logItems.add(checkTasksMenuItem);

            JMenuItem runningMenuItem = new JMenuItem("Log Uncompleted Tasks");
            runningMenuItem.addActionListener(e -> {
                api.logging().logToOutput("[=============== Uncompleted Tasks =============]");

                int runningTasksSize = taskRepository.getRunningTasks().size();
                // If there was some timed out tasks, print them for troubleshooting or local checking
                if (runningTasksSize > 0) {
                    api.logging().logToOutput("Running tasks:" + taskRepository.printRunningTasks().toString());
                    api.logging().logToOutput("=============================================");
                }

                int failedTasksSize = taskRepository.getFailedTasks().size();
                // If there was some timed out tasks, print them for troubleshooting or local checking
                if (failedTasksSize > 0) {
                    api.logging().logToOutput("Failed tasks:" + taskRepository.printFailedTasks().toString());
                    api.logging().logToOutput("=============================================");
                }
            });
            logItems.add(runningMenuItem);

            // === Configuration Menu Items ==== //
            JMenuItem toggleLoggingMenuItem = new JMenuItem(extensionConfig.loggingConfigMenuItemText());
            toggleLoggingMenuItem.addActionListener(e -> {
                extensionConfig.toggleLogging();
                updateExtensionConfig();
            });
            configItems.add(toggleLoggingMenuItem);

            JMenuItem toggleBurpPassiveScanMenuItem = new JMenuItem(extensionConfig.passiveConfigMenuItemText());
            toggleBurpPassiveScanMenuItem.addActionListener(e -> {
                extensionConfig.togglePassiveScans();
                updateExtensionConfig();
            });
            configItems.add(toggleBurpPassiveScanMenuItem);

            items.add(configItems);
            items.add(scanItems);
            items.add(logItems);
        }
        return items;
    }

    private List<MenuItem> createScanMenuItems(List<HttpRequestResponse> messages) {
        List<MenuItem> menuItems = new ArrayList<>();
        
        // All passive scans
        menuItems.add(MenuItem.builder()
            .text("Run all passive scans")
            .action(e -> runScan(messages, ScannerBuilder.Builder::runAllPassiveScans))
            .build());
            
        // JS source mapper
        menuItems.add(MenuItem.builder()
            .text("JS source mapper (active)")
            .action(e -> runScan(messages, ScannerBuilder.Builder::activeSourceMapperScan))
            .build());
            
        // Secrets scan
        menuItems.add(MenuItem.builder()
            .text("Secrets")
            .action(e -> runScan(messages, ScannerBuilder.Builder::scanSecrets))
            .build());
            
        // Dependency Confusion
        menuItems.add(MenuItem.builder()
            .text("Dependency Confusion")
            .action(e -> runScan(messages, ScannerBuilder.Builder::scanDependencyConfusion))
            .build());
            
        // SubDomains
        menuItems.add(MenuItem.builder()
            .text("SubDomains")
            .action(e -> runScan(messages, ScannerBuilder.Builder::scanSubDomains))
            .build());
            
        // Cloud URLs
        menuItems.add(MenuItem.builder()
            .text("Cloud URLs")
            .action(e -> runScan(messages, ScannerBuilder.Builder::scanCloudURLs))
            .build());
            
        // Inline Source Maps
        menuItems.add(MenuItem.builder()
            .text("Inline B64 JS Source Maps")
            .action(e -> runScan(messages, ScannerBuilder.Builder::scanInlineSourceMapFiles))
            .build());
            
        // Dump Static Files
        menuItems.add(MenuItem.builder()
            .text("Dump Static Files")
            .action(e -> runScan(messages, ScannerBuilder.Builder::dumpStaticFiles))
            .build());
            
        // API Endpoints Finder
        menuItems.add(MenuItem.builder()
            .text("API Endpoints Finder")
            .action(e -> runScan(messages, ScannerBuilder.Builder::endpointsFinder))
            .build());
            
        return menuItems;
    }

    private void runScan(List<HttpRequestResponse> messages, Function<ScannerBuilder.Builder, ScannerBuilder.Builder> scanType) {
        new Thread(() -> {
            ScannerBuilder scannerBuilder = scanType.apply(new ScannerBuilder.Builder(messages.toArray(new HttpRequestResponse[0])))
                .taskId(++taskCount)
                .build();
            scannerBuilder.runScans();
        }).start();
    }

    private List<MenuItem> createConfigMenuItems() {
        List<MenuItem> menuItems = new ArrayList<>();
        
        menuItems.add(MenuItem.builder()
            .text(extensionConfig.loggingConfigMenuItemText())
            .action(e -> {
                extensionConfig.toggleLogging();
                updateExtensionConfig();
            })
            .build());
            
        menuItems.add(MenuItem.builder()
            .text(extensionConfig.passiveConfigMenuItemText())
            .action(e -> {
                extensionConfig.togglePassiveScans();
                updateExtensionConfig();
            })
            .build());
            
        return menuItems;
    }

    private List<MenuItem> createLogMenuItems() {
        List<MenuItem> menuItems = new ArrayList<>();
        
        menuItems.add(MenuItem.builder()
            .text("Check tasks")
            .action(e -> {
                api.logging().logToOutput("[=============== Tasks Summary =============]");
                api.logging().logToOutput("Total Tasks: " + taskRepository.getSize());
                api.logging().logToOutput("Queued tasks: " + taskRepository.getQueuedTasks().size());
                api.logging().logToOutput("Completed tasks: " + taskRepository.getCompletedTasks().size());
                api.logging().logToOutput("Running tasks: " + taskRepository.getRunningTasks().size());
                api.logging().logToOutput("Failed tasks: " + taskRepository.getFailedTasks().size());
                api.logging().logToOutput("============================================");
            })
            .build());
            
        menuItems.add(MenuItem.builder()
            .text("Print uncompleted tasks")
            .action(e -> {
                api.logging().logToOutput("[=============== Uncompleted Tasks =============]");
                int runningTasksSize = taskRepository.getRunningTasks().size();
                if (runningTasksSize > 0) {
                    api.logging().logToOutput("Running tasks:" + taskRepository.printRunningTasks());
                    api.logging().logToOutput("=============================================");
                }
                int failedTasksSize = taskRepository.getFailedTasks().size();
                if (failedTasksSize > 0) {
                    api.logging().logToOutput("Failed tasks:" + taskRepository.printFailedTasks());
                    api.logging().logToOutput("=============================================");
                }
            })
            .build());
            
        return menuItems;
    }

}