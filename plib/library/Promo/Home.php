<?php

class Modules_PleskExtensionsVirustotal_Promo_Home extends pm_Promo_AdminHome
{
    public function getTitle()
    {
        pm_Context::init('virustotal-site-checker');
        return $this->lmsg('virustotalPromoTitle');
    }
    public function getText()
    {
        pm_Context::init('virustotal-site-checker');

        $total_domains = (int)pm_Settings::get('total_domains_checked');
        $last_scan = pm_Settings::get('last_scan');

        if ($last_scan) {
            $text = $this->lmsg('totalDomains') . $total_domains . ', ' . $this->lmsg('lastScan') . $last_scan;
        } else {
            $text = $this->lmsg('scanningWasNotPerformedYet');
        }

        $admin_report = json_decode(pm_Settings::get('admin_report'), true);
        if ($admin_report) {
            $text = $this->lmsg('totalReports') . count($admin_report['domains']) . $this->lmsg('ofTotalDomains') . $total_domains . ', ' . $this->lmsg('lastScan') . $last_scan;
        }

        pm_Settings::set('report_summary', $text);

        return $text;
    }
    public function getButtonText()
    {
        pm_Context::init('virustotal-site-checker');
        return $this->lmsg('virustotalPromoButtonTitle');
    }
    public function getButtonUrl()
    {
        pm_Context::init('virustotal-site-checker');
        return pm_Context::getBaseUrl();
    }
    public function getIconUrl()
    {
        pm_Context::init('virustotal-site-checker');
        return pm_Context::getBaseUrl() . '/images/virus-total.png';
    }
}