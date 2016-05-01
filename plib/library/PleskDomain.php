<?php

class Modules_PleskExtensionsVirustotal_PleskDomain
{
    function __construct($id, $name, $ascii_name, $status, $dns_ip_address, $htype) {
        $this->id = $id;
        $this->name = $name;
        $this->ascii_name = $ascii_name;
        $this->status = $status;
        $this->dns_ip_address = $dns_ip_address;
        $this->htype = $htype;
    }

    private function isResolvingToPlesk() {
        /*
           array(5) {
              [0]=>
                array(5) {
                    ["host"]=>  string(9) "gmail.com"
                    ["class"]=> string(2) "IN"
                    ["ttl"]=>   int(147)
                    ["type"]=>  string(1) "A"
                    ["ip"]=>    string(14) "173.194.222.17"
                  }
              [4]=>
              array(5) {
                ["host"]=>      string(9) "gmail.com"
                ["class"]=>     string(2) "IN"
                ["ttl"]=>       int(87)
                ["type"]=>      string(4) "AAAA"
                ["ipv6"]=>      string(22) "2a00:1450:4010:c07::11"
              }
            }
         */
        $records = dns_get_record($this->ascii_name, DNS_A|DNS_AAAA);
        foreach ($records as $r) {
            $ip = '';
            if (isset($r['ip'])) {
                $ip = $r['ip'];
            } elseif (isset($r['ipv6'])) {
                $ip = $r['ipv6'];
            }
            
            if ($ip === $this->dns_ip_address) {
                return true;
            }
        }
        return false;
    }

    public function isValid() {
        if ($this->status > 0) {
            return false;
        } elseif (!$this->isResolvingToPlesk()) {
            return false;
        }
        
        return true;
    }
}