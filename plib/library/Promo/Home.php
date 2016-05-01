<?php

class Modules_PleskExtensionsVirustotal_Promo_Home extends pm_Promo_AdminHome
{
    public function getTitle()
    {
        pm_Context::init('plesk-extensions-virustotal');
        return $this->lmsg('virustotalPromoTitle');
    }
    public function getText()
    {
        pm_Context::init('plesk-extensions-virustotal');
        $text = (string)pm_Settings::get('promo_text');
        return $text ? $text : $this->lmsg('noReports');
    }
    public function getButtonText()
    {
        pm_Context::init('plesk-extensions-virustotal');
        return $this->lmsg('virustotalPromoButtonTitle');
    }
    public function getButtonUrl()
    {
        pm_Context::init('plesk-extensions-virustotal');
        return pm_Context::getBaseUrl();
    }
    public function getIconUrl()
    {
        pm_Context::init('plesk-extensions-virustotal');
        return pm_Context::getBaseUrl() . '/images/virus-total.png';
    }
}