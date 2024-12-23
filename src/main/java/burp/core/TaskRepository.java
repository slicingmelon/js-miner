package burp.core;

import burp.api.montoya.MontoyaApi;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static burp.utils.Constants.LOG_FORMAT;
import static burp.utils.Constants.LOG_TASK_ID_PREFIX;
import burp.config.ExtensionConfig;

public class TaskRepository {
    private static TaskRepository taskRepository = null;
    private static MontoyaApi api;
    private final List<Task> tasks = new CopyOnWriteArrayList<>();
    private static final String LINE_SEPARATOR = System.lineSeparator();

    public static void setApi(MontoyaApi api) {
        TaskRepository.api = api;
    }

    public static TaskRepository getInstance() {
        if (taskRepository == null)
            taskRepository = new TaskRepository();
        return taskRepository;
    }

    private TaskRepository() {
    }

    public void addTask(Task task) {
        getTasks().add(task);
        logTask(task);
    }

    public boolean notDuplicate(TaskName taskName, String url, byte[] hash) {
        String normalizedURL = Task.normalizeURL(url);
        for (Task task : getTasks()) {
            if (Arrays.equals(task.getHash(), hash)
                    && task.getUrl().equals(normalizedURL)
                    && task.getName().equals(taskName)) {
                return task.getStatus().equals(TaskStatus.FAILED);
            }
        }
        return true;
    }

    public Task findTaskByUUID(UUID taskUUID) {
        return getTasks().stream()
                .filter(task -> task.getUuid().equals(taskUUID))
                .findFirst()
                .orElse(null);
    }

    public List<Task> getQueuedTasks() {
        return getTasks().stream()
                .filter(task -> task.getStatus().equals(TaskStatus.QUEUED))
                .toList();
    }

    public List<Task> getCompletedTasks() {
        return getTasks().stream()
                .filter(task -> task.getStatus().equals(TaskStatus.COMPLETED))
                .toList();
    }

    public List<Task> getRunningTasks() {
        return getTasks().stream()
                .filter(task -> task.getStatus().equals(TaskStatus.RUNNING))
                .toList();
    }

    public List<Task> getFailedTasks() {
        return getTasks().stream()
                .filter(task -> task.getStatus().equals(TaskStatus.FAILED))
                .toList();
    }

    public StringBuilder printRunningTasks() {
        StringBuilder tasksSB = new StringBuilder();
        getTasks().stream()
                .filter(task -> task.getStatus().equals(TaskStatus.RUNNING))
                .forEach(task -> tasksSB.append(LINE_SEPARATOR).append(task));
        return tasksSB;
    }

    public StringBuilder printFailedTasks() {
        StringBuilder tasksSB = new StringBuilder();
        getTasks().stream()
                .filter(task -> task.getStatus().equals(TaskStatus.FAILED))
                .forEach(task -> tasksSB.append(LINE_SEPARATOR).append(task));
        return tasksSB;
    }

    public void startTask(UUID taskId) {
        updateTaskStatus(taskId, TaskStatus.RUNNING);
    }

    public void completeTask(UUID taskId) {
        updateTaskStatus(taskId, TaskStatus.COMPLETED);
    }

    public void failTask(UUID taskId) {
        updateTaskStatus(taskId, TaskStatus.FAILED);
    }

    private void updateTaskStatus(UUID taskId, TaskStatus status) {
        Task task = findTaskByUUID(taskId);
        if (task != null) {
            task.setStatus(status);
            logTask(task);
        }
    }

    public void destroy() {
        tasks.clear();
    }

    public int getSize() {
        return getTasks().size();
    }

    private synchronized List<Task> getTasks() {
        return tasks;
    }

    private static void logTask(Task task) {
        if (task.getId() != -1 && ExtensionConfig.getInstance().isVerboseLogging()) {
            api.logging().logToOutput(
                String.format(LOG_FORMAT, 
                    "[" + task.getStatus() + "]", 
                    LOG_TASK_ID_PREFIX + task.getId(), 
                    task.getName(), 
                    task.getUrl())
            );
        }
    }
}
