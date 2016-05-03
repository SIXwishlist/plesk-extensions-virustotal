<?php

class Modules_VirustotalSiteChecker_Helper
{
    const virustotal_scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan';
    const virustotal_report_url = 'https://www.virustotal.com/vtapi/v2/url/report';
    const virustotal_domain_info_url = 'https://www.virustotal.com/domain/%s/information/';
    const virustotal_api_timeout = 20;
    const virustotal_api_day_limit = 4300;

    public static  function check()
    {
        pm_Settings::set('total_domains_checked', 0);
        
        if (!pm_Settings::get('virustotal_enabled') || !pm_Settings::get('virustotal_api_key')) {
            return;
        }

        self::cleanup_admin_report();
        self::report();

        foreach (self::getDomains() as $domain) {
            if (!self::is_last_domain('check', $domain)) {
                continue;
            }
            if (self::is_enough()) {
                exit(0);
            }
            
            
            $request = json_decode(pm_Settings::get('domain_id_' . $domain->id), true);
            if ($request && !$request['virustotal_request_done']) {
                continue;
            }
            
            if (!$domain->isValid()) {
                continue;
            }
            
            $virustotal_request = array(
                'domain' => $domain,
                'virustotal_request_done' => false,
                'virustotal_request' => self::virustotal_scan_url_request($domain->ascii_name)
            );

            pm_Settings::set('domain_id_' . $domain->id, json_encode($virustotal_request));
            pm_Settings::set('last_scan', date("d/M/Y G:i"));
            pm_Settings::set('total_domains_checked', pm_Settings::get('total_domains_checked') + 1);
        }

        self::cleanup_last_domains();
    }

    /**
     * VirusTotal API has restriction in 4 req/min, for safety we have limit to 3 req/min (4320 req/day)
     * 
     * @return bool
     */
    public static function is_enough()
    {
        static $counter = 0;
        if ($counter >= self::virustotal_api_day_limit) {
            return true;
        }
        $counter++;
        return false;
    }

    /**
     * @param  $operation string
     * @param  $domain Modules_VirustotalSiteChecker_PleskDomain
     * @return bool
     */
    public static function is_last_domain($operation, $domain)
    {
        $last = json_decode(pm_Settings::get('last_domain_' . $operation), true);
        if (!$last) {
            pm_Settings::set('last_domain_' . $operation, json_encode($domain));
            return true;
        }

        if ($domain->id < $last['id']) {
            return false;
        }

        pm_Settings::set('last_domain_' . $operation, json_encode($domain));
        return true;
    }

    public static function report()
    {
        foreach (self::getDomains() as $domain) {
            if (!self::is_last_domain('report', $domain)) {
                continue;
            }
            if (self::is_enough()) {
                exit(0);
            }

            $request = json_decode(pm_Settings::get('domain_id_' . $domain->id), true);
            if (!$request) {
                continue;
            }

            $report = self::virustotal_scan_url_report($domain->ascii_name);
            //error_log(print_r($report, 1));
            if (isset($report['positives'])) {
                $request['virustotal_request_done'] = true;
                $request['virustotal_report_positives'] = $report['positives'];
                pm_Settings::set('domain_id_' . $domain->id, json_encode($request));

                if ($report['positives'] > 0) {
                    self::report_domain($domain, $report);
                } else {
                    self::unreport_domain($domain);
                }
            }
        }

        self::cleanup_last_domains();
    }

    public static function cleanup_last_domains()
    {
        $ops = ['report', 'check'];
        foreach ($ops as $operation) {
            pm_Settings::set('last_domain_' . $operation, false);
        }
    }

    public static function cleanup_admin_report()
    {
        $admin_report = json_decode(pm_Settings::get('admin_report'), true);
        if (!is_array($admin_report)) {
            return;
        }

        $to_delete = [];
        $domains = self::getDomains();
        foreach ($admin_report['domains'] as $key => $report) {
            if (!isset($domains[$report['domain']['id']])) {
                $to_delete[] = $key;
            }
        }
        foreach ($to_delete as $key) {
            unset($admin_report['domains'][$key]);
        }

        pm_Settings::set('admin_report', json_encode($admin_report));
    }

    /**
     * @param $domain Modules_VirustotalSiteChecker_PleskDomain
     * @return null
     */
    public static function unreport_domain($domain)
    {
        $admin_report = json_decode(pm_Settings::get('admin_report'), true);
        if (!is_array($admin_report)) {
            return;
        }

        unset($admin_report['domains'][$domain->ascii_name]);
        pm_Settings::set('admin_report', json_encode($admin_report));
    }

    /**
     * @param $domain Modules_VirustotalSiteChecker_PleskDomain
     * @param $report array
     * @return null
     */
    public static function report_domain($domain, $report)
    {
        $admin_report = json_decode(pm_Settings::get('admin_report'), true);
        if (!is_array($admin_report)) {
            $admin_report = array(
                'domains' => []
            );
        }

        $admin_report['domains'][$domain->ascii_name] = array(
            'domain' => $domain,
            'virustotal_domain_info_url' => sprintf(self::virustotal_domain_info_url, $domain->ascii_name),
            'virustotal_positives' => $report['positives'],
            'virustotal_total' => isset($report['total']) ? $report['total'] : '',
            'virustotal_scan_date' => isset($report['scan_date']) ? $report['total'] : ''
        );

        pm_Settings::set('admin_report', json_encode($admin_report));
    }

    /**
     * @param $url string
     * @return array
     */
    public static function virustotal_scan_url_request($url)
    {
        $client = new Zend_Http_Client(self::virustotal_scan_url);

        $client->setParameterPost('url', $url);
        $client->setParameterPost('apikey', pm_Settings::get('virustotal_api_key'));
        sleep(self::virustotal_api_timeout);
        $response = $client->request(Zend_Http_Client::POST);

        return json_decode($response->getBody(), true);
    }

    /**
     * @param $url string
     * @return array
     */
    public static function virustotal_scan_url_report($url)
    {
        $client = new Zend_Http_Client(self::virustotal_report_url);

        $client->setParameterPost('resource', $url);
        $client->setParameterPost('apikey', pm_Settings::get('virustotal_api_key'));
        sleep(self::virustotal_api_timeout);
        $response = $client->request(Zend_Http_Client::POST);

        return json_decode($response->getBody(), true);
    }

    /**
     * @return Modules_VirustotalSiteChecker_PleskDomain[]
     */
    public static function getDomains()
    {
        static $domains = [];
        if ($domains) {
            return $domains;
        }
        $sites_request = '<site><get><filter/><dataset><gen_info/></dataset></get></site>';
        $websp_request = '<webspace><get><filter/><dataset><gen_info/></dataset></get></webspace>';
        $api = pm_ApiRpc::getService();
        // site->get->result->[ id, data -> gen_info ( [cr_date] , [name] , [ascii-name] , [status] => 0 , [dns_ip_address] , [htype] )
        $sites_response = $api->call($sites_request);
        $websp_response = $api->call($websp_request);

        $sites = json_decode(json_encode($sites_response->site->get));
        $websp = json_decode(json_encode($websp_response->webspace->get));

        $sites_array =  is_array($sites->result) ? $sites->result : array($sites->result);
        $websp_array =  is_array($websp->result) ? $websp->result : array($websp->result);

        $tmp_list = array_merge($sites_array, $websp_array);
        foreach ($tmp_list as $domain) {

            $domains[$domain->id] = new Modules_VirustotalSiteChecker_PleskDomain(
                $domain->id,
                $domain->data->gen_info->name,
                $domain->data->gen_info->{'ascii-name'},
                $domain->data->gen_info->status,
                is_array($domain->data->gen_info->dns_ip_address) ? $domain->data->gen_info->dns_ip_address : array($domain->data->gen_info->dns_ip_address),
                $domain->data->gen_info->htype,
                $domain->data->gen_info->{'webspace-id'}
            );
        }

        ksort($domains);
        return $domains;
    }
}