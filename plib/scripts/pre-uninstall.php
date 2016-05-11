<?php

pm_Context::init('virustotal-site-checker');

pm_Scheduler::getInstance()->removeAllTasks();

pm_Settings::clean();