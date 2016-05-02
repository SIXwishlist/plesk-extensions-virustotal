<?php

pm_Context::init('plesk-extensions-virustotal');

$taskId = pm_Settings::get('virustotal_periodic_task_id');
if (!$taskId) {
    return;
}

try {
    $task = pm_Scheduler::getInstance()->getTaskById($taskId);
    pm_Scheduler::getInstance()->removeTask($task);
} catch (pm_Exception $e) {
    echo $e->getMessage();
}

pm_Settings::clean();