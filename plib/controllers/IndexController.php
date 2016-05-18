<?php
// plesk bin extension --create my-extension
// plesk bin extension --register my-extension

class IndexController extends pm_Controller_Action
{
    public function init()
    {
        $this->_accessLevel = 'admin';
        
        parent::init();
        
        
        $this->view->pageTitle = $this->lmsg('pageTitle');
        
        $this->view->tabs = [
            [
                'title' => $this->lmsg('tabReports'),
                'action' => 'report',
            ],
            [
                'title' => $this->lmsg('tabSettings'),
                'action' => 'settings',
            ],
            [
                'title' => $this->lmsg('tabAbout'),
                'action' => 'about',
            ],
        ];
    }

    public function indexAction()
    {
        if (!pm_Settings::get('virustotal_enabled') || pm_Settings::get('apiKeyBecameInvalid')) {
            $this->_forward('settings');
            return;
        }

        $this->_forward('report');
    }

    public function reportAction()
    {
        if (!pm_Settings::get('virustotal_enabled')) {
            $this->_forward('settings');
            return;
        }
        
        $this->view->summary = $this->_getReportSummary();
        $this->view->list = $this->_getDomainsReportList();

    }

    public function reportDataAction()
    {
        $list = $this->_getDomainsReportList();
        // Json data from pm_View_List_Simple
        $this->_helper->json($list->fetchData());
    }
    
    public function settingsAction() 
    {
        if (pm_Settings::get('apiKeyBecameInvalid')) {
            $this->view->api_key_invalid = $this->lmsg('apiKeyBecameInvalid');
        }
        
        $this->view->help_tip = $this->lmsg('apikey_help');

        $form = new Modules_VirustotalSiteChecker_SettingsForm();

        $form->addElement('checkbox', 'virustotal_enabled', [
            'label' => $this->lmsg('virustotalEnabled'),
            'value' => pm_Settings::get('virustotal_enabled'),
        ]);

        $form->addElement('text', 'virustotal_api_key', [
            'label' => $this->lmsg('virustotalPublicApiKey'),
            'value' => pm_Settings::get('virustotal_api_key'),
            'required' => true,
            'validators' => [
                ['NotEmpty', true],
            ],
        ]);

        $form->addElement('checkbox', '_promo_admin_home', [
            'label' => $this->lmsg('adminHomeWidgetEnabled'),
            'value' => pm_Settings::get('_promo_admin_home'),
        ]);

        $form->addControlButtons([
            'cancelLink' => pm_Context::getModulesListUrl(),
        ]);

        if ($this->getRequest()->isPost() && $form->isValid($this->getRequest()->getPost())) {

            pm_Settings::set('apiKeyBecameInvalid', '');
            pm_Settings::set('virustotal_enabled', $form->getValue('virustotal_enabled'));
            pm_Settings::set('virustotal_api_key', $form->getValue('virustotal_api_key'));
            pm_Settings::set('_promo_admin_home', $form->getValue('_promo_admin_home'));
            
            $this->_status->addMessage('info', $this->lmsg('settingsWasSuccessfullySaved'));
            $this->_helper->json(['redirect' => pm_Context::getBaseUrl()]);
        }

        $this->view->form = $form;
    }

    public function aboutAction()
    {
        $this->view->about = $this->lmsg('about');
        $this->view->feedback = $this->lmsg('feedback');
        $this->view->faq = $this->lmsg('faq');
        $this->view->question1 = $this->lmsg('question1');
        $this->view->question2 = $this->lmsg('question2');
        $this->view->question3 = $this->lmsg('question3');
    }
    
    private function _getReportSummary()
    {
        $report = Modules_VirustotalSiteChecker_Helper::getDomainsReport();
                
        $total_domains = $report['total'];
        $last_scan = pm_Settings::get('last_scan');

        if ($last_scan) {
            $text = $this->lmsg('totalDomains') . $total_domains . ', ' . $this->lmsg('lastScan') . $last_scan;
        } else {
            $text = $this->lmsg('scanningWasNotPerformedYet') . ' ' . $this->lmsg('youCanStartTaskAt');
        }
        
        if (count($report['bad']) > 0) {
            $text = $this->lmsg('totalReports') . count($report['bad']) . $this->lmsg('ofTotalDomains') . $total_domains . ', ' . $this->lmsg('lastScan') . $last_scan;
        }

        return $text;
    }
    
    private function _getDomainsReportList() 
    {
        $i = 0;
        $data = [];
        $report = Modules_VirustotalSiteChecker_Helper::getDomainsReport();
        foreach ($report['all'] as $domain) {
            $i++;

            $scan_date_column = isset($domain->virustotal_scan_date) ? $domain->virustotal_scan_date : '';
            if (isset($domain->no_scanning_results)) {
                $result_column = $domain->no_scanning_results;
                $report_link_column = '';
            } else {
                $result_column = $domain->virustotal_positives . ' / ' . $domain->virustotal_total;
                $report_link_column = '<a rel="noopener noreferrer" target="_blank" href="' . $domain->virustotal_domain_info_url . '">' .  $this->lmsg('virustotalReport') . '</a>';
            }
            
            $data[$i] = [
                'column-1' => '<a target="_blank" href="/admin/subscription/login/id/' . $domain->webspace_id . '?pageUrl=/web/overview/id/d:' . $domain->id . '">' . $domain->name . '</a>',
                'column-2' => $domain->getAvailable(),
                'column-3' => $scan_date_column,
                'column-4' => $result_column,
                'column-5' => $report_link_column,
            ];
        }
        
        if (!count($data) > 0) {
            return new pm_View_List_Simple($this->view, $this->_request);
        }
        
        $options = [
            'defaultSortField' => 'column-1',
            'defaultSortDirection' => pm_View_List_Simple::SORT_DIR_DOWN,
        ];
        $list = new pm_View_List_Simple($this->view, $this->_request, $options);
        $list->setData($data);
        $list->setColumns([
            'column-1' => [
                'title' => $this->lmsg('domain'),
                'noEscape' => true,
                'searchable' => true,
                'sortable' => true,
            ],
            'column-2' => [
                'title' => $this->lmsg('availableForScanning'),
                'searchable' => false,
                'sortable' => true,
            ],
            'column-3' => [
                'title' => $this->lmsg('scanDate'),
                'sortable' => true,
            ],
            'column-4' => [
                'title' => $this->lmsg('checkResult'),
                'sortable' => true,
            ],
            'column-5' => [
                'title' => $this->lmsg('reportLink'),
                'noEscape' => true,
                'searchable' => false,
                'sortable' => false,
                
            ],
        ]);

        $list->setDataUrl(['action' => 'report-data']);
        return $list;
    }

}
