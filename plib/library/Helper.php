<?php

class Modules_PleskExtensionsVirustotal_Helper
{

    public static  function check()
    {
        $queue = [];

        foreach (self::getDomains() as $domain) {

        }
    }

    public function virustotal_check_url($url)
    {

    }

    public function getDomains()
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