<?php
// plesk bin extension --create my-extension
// plesk bin extension --register my-extension

class IndexController extends pm_Controller_Action
{
    public function init()
    {
        parent::init();

        $this->view->pageTitle = $this->lmsg('pageTitle');
        
        $this->view->tabs = [
            [
                'title' => 'Report',
                'action' => 'report',
            ],
            [
                'title' => 'Settings',
                'action' => 'settings',
            ],
            [
                'title' => 'About',
                'action' => 'about',
            ],
        ];
    }

    public function indexAction()
    {
        if (!pm_Settings::get('virustotal_enabled')) {
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
    
    public function settingsAction() 
    {
        $this->view->help_tip = $this->lmsg('apikey_help');

        $form = new pm_Form_Simple();

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
        $this->view->question3 = $this->lmsg('question3', ['image' => pm_Context::getBaseUrl() . '/images/faq-3.png']);
    }
    
    private function _getReportSummary()
    {
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
    
    private function _getDomainsReportList() 
    {
        $admin_report = json_decode(pm_Settings::get('admin_report'), true);
        if (!$admin_report) {
            return new pm_View_List_Simple($this->view, $this->_request);
        }
        $i = 0;
        $data = [];
        foreach ($admin_report['domains'] as $domain) {
            $i++;
            
            $data[$i] = [
                'column-1' => $i,
                'column-2' => '<a target="_blank" href="/admin/subscription/login/id/' . $domain['domain']['webspace_id'] . '?pageUrl=/web/overview/id/d:' . $domain['domain']['id'] . '">' . $domain['domain']['name'] . '</a>',
                'column-3' => $domain['virustotal_positives'] . ' / ' . $domain['virustotal_total'],
                'column-4' => '<a rel="noopener noreferrer" target="_blank" href="' . $domain['virustotal_domain_info_url'] . '">' .  $this->lmsg('virustotalReport') . '</a>',
            ];
        }
        
        $options = [
            'defaultSortField' => 'column-1',
            'defaultSortDirection' => pm_View_List_Simple::SORT_DIR_DOWN,
        ];
        $list = new pm_View_List_Simple($this->view, $this->_request, $options);
        $list->setData($data);
        $list->setColumns([
            pm_View_List_Simple::COLUMN_SELECTION,
            'column-1' => [
                'title' => '#',
                'noEscape' => true,
                'searchable' => true,
            ],
            'column-2' => [
                'title' => $this->lmsg('domain'),
                'noEscape' => true,
                'sortable' => false,
            ],
            'column-3' => [
                'title' => $this->lmsg('positives'),
                'noEscape' => true,
                'sortable' => false,
            ],
            'column-4' => [
                'title' => $this->lmsg('reportLink'),
                'noEscape' => true,
                'sortable' => false,
            ],
        ]);

        $list->setDataUrl(['action' => 'report']);
        return $list;
    }

}
