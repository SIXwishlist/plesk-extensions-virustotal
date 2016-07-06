<?php
// Copyright 1999-2016. Parallels IP Holdings GmbH.
$messages = array(
    'tabReports' => 'Reports',
    'tabSettings' => 'Settings',
    'tabAbout' => 'About',
    'pageTitle' => 'Website Virus Check',
    'virustotalEnabled' => 'Enable scanning',
    'virustotalPublicApiKey' => 'Vendor Public API key',
    'adminHomeWidgetEnabled' => 'Add a widget with scan notifications to Administrator\'s home page',
    'settingsWasSuccessfullySaved' => 'Settings successfully saved.',
    'settingsFormApiInvalid' => 'API key is invalid. HTTP status code: %%code%%',
    'apiKeyBecameInvalid' => 'Last API request has finished with HTTP error 403',
    'buttonStartScan' => 'Start',
    'buttonStopScan' => 'Stop',
    'buttonStartDesc' => 'Start Scanning',
    'buttonStopDesc' => 'Stop Scanning',
    'infoStartSuccess' => 'Scanning started',
    'infoStopSuccess' => 'Scanning stopped',
    'scanTaskRunning' => 'Scanning sites for viruses:',
    'scanTaskDone' => 'Scanning of sites finished. <a href="#" onclick="window.location.reload();">Refresh page</a>',
    'errorScanAlreadyRunning' => 'Scanning is already running.',
    'domain' => 'Domain',
    'availableForScanning' => 'Available for scanning',
    'yes' => 'Yes',
    'no' => 'No',
    'unknown' => 'Unknown',
    'domainInactiveOrCantbeResolvedInHostingIp' => 'Domain is "Suspended", "Disabled" or can\'t be resolved in hosting IP address',
    'scanDate' => 'Last scan Date',
    'checkResult' => 'Detection ratio',
    'reportLink' => 'Link to scan report',
    'virustotalReport' => 'Open',
    'apikey_help' => 'You can get a free API key after you register at <a rel="noopener noreferrer" target=\'_blank\' href=\'https://virustotal.com/\'>API vendor site</a>',
    'virustotalPromoTitle' => 'Virus Reports',
    'virustotalPromoButtonTitle' => 'More info',
    'scanningWasNotPerformedYet' => 'Scanning was not performed yet.',
    'youCanStartTaskAt' => 'You can start scheduled task for scanning now at <a href="/admin/scheduler/tasks-list">Scheduled Tasks</a>',
    'scanningWasNotPerformedYetForList' => 'Scanning was not performed yet',
    'scanningRequestIsSent' => 'Scanning request is sent',
    'totalDomains' => 'Domains scanned: ',
    'ofTotalDomains' => ' of all domains selected for scanning ',
    'totalReports' => 'Total "bad" domains: ',
    'lastScan' => 'last scanning performed on ',
    'about' => 'This extension uses the <a rel="noopener noreferrer" target=\'_blank\' href=\'https://virustotal.com/\'>public API</a> to detect malicious scripts on your websites. API requests are executed using daily scheduled tasks at <a href="/admin/scheduler/tasks-list">Scheduled Tasks</a>',
    'feedback' => 'Submit any questions to <a rel="noopener noreferrer" target="_blank" href="http://serverfault.com/questions/ask?tags=plesk+virustotal">serverfault.com</a> using the tags "plesk" and "virustotal"',
    'faq' => 'FAQ',
    'question1' => '<p><b>Q: Why there are no e-mail notifications?</b><br />A: We have no way of knowing that e-mails will reach your inbox.</p>',
    'question2' => '<p><b>Q: Why daily scheduled tasks take so long to execute?</b><br />A: Because of the limitations of the public API the extension sends the API requests at the speed of 3 domains per minute.</p>',
    'question3' => '<p><b>Q: Can I execute daily scheduled task several times in a one day?</b><br />A: Yes, you can.</p>',
);