<?php

class Modules_VirustotalSiteChecker_Task_Scan extends pm_LongTask_Task
{
    public $trackProgress = true;

    public function run()
    {
        sleep(2);
        $this->updateProgress(30);
        sleep(2);
        $this->updateProgress(60);
        sleep(2);
        $this->updateProgress(90);
        sleep(2);
    }

    public function statusMessage()
    {
        switch ($this->getStatus()) {
            case static::STATUS_QUEUE:
                return pm_Locale::lmsg('queued');
            case static::STATUS_DONE:
                return pm_Locale::lmsg('done', ['id' => $this->getId()]);
        }
        return '';
    }

    public function onStart()
    {
        $this->setParam('onStart', 1);
    }

    public function onDone()
    {
        $this->setParam('onDone', 1);
    }
}