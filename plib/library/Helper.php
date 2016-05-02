<?php

class Modules_PleskExtensionsVirustotal_Helper
{
    const virustotal_scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan';
    const virustotal_report_url = 'https://www.virustotal.com/vtapi/v2/url/report';
    const virustotal_api_timeout = 20;

    public static  function check()
    {
        if (!pm_Settings::get('virustotal_enabled') || !pm_Settings::get('virustotal_api_key')) {
            return;
        }

        self::report();

        foreach (self::getDomains() as $domain) {
            $request = json_decode(pm_Settings::get('domain_id_' . $domain->id));
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
        }
    }

    public static function report()
    {
        foreach (self::getDomains() as $domain) {
            $request = json_decode(pm_Settings::get('domain_id_' . $domain->id));
            if (!$request) {
                continue;
            }

            $report = self::virustotal_scan_url_report($domain->ascii_name);
            if (isset($report['positives'])) {

                $request['virustotal_request_done'] = true;
                
                if ($report['positives'] > 0) {
                    $admin_report = json_decode(pm_Settings::get('admin_report'));
                    if (!is_array($admin_report)) {
                        $admin_report = array();
                    }
    
                    $admin_report[] = array(
                        'domain' => $domain,
                        'virustotal_request' => $request['virustotal_request'],
                        'virustotal_report' => $report
                    );
    
                    pm_Settings::set('admin_report', json_encode($admin_report));
                }

                pm_Settings::set('domain_id_' . $domain->id, json_encode($request));
            }
        }
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

        return json_decode($response->getBody());
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

        return json_decode($response->getBody());
    }

    /**
     * @return Modules_PleskExtensionsVirustotal_PleskDomain[]
     */
    public static function getDomains()
    {
        $domains = [];
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

            $domains[] = new Modules_PleskExtensionsVirustotal_PleskDomain(
                $domain->id,
                $domain->data->gen_info->name,
                $domain->data->gen_info->{'ascii-name'},
                $domain->data->gen_info->status,
                is_array($domain->data->gen_info->dns_ip_address) ? $domain->data->gen_info->dns_ip_address : array($domain->data->gen_info->dns_ip_address),
                $domain->data->gen_info->htype
            );
        }

        return $domains;
    }
}