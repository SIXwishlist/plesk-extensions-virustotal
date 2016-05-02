<?php
// plesk bin extension --create my-extension
// plesk bin extension --register my-extension

class IndexController extends pm_Controller_Action
{
    public function init()
    {
        parent::init();

        // Init title for all actions
        $this->view->pageTitle = $this->lmsg('pageTitle', ['product' => 'Plesk']);

        // Init tabs for all actions
        $this->view->tabs = [
            [
                'title' => 'Report',
                'action' => 'report',
            ],
            [
                'title' => 'Settings',
                'action' => 'settings',
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

        $this->view->list = $this->_getDomainsReportList();

    }
    
    public function settingsAction() 
    {
        $this->view->help_tip = $this->lmsg('apikey_help');
        $this->view->debug = print_r(json_encode($this->_getDomainsReportList()), 1);

        $form = new pm_Form_Simple();

        $form->addElement('checkbox', 'virustotal_enabled', [
            'label' => 'Virustotal Enabled',
            'value' => pm_Settings::get('virustotal_enabled'),
        ]);

        $form->addElement('text', 'virustotal_api_key', [
            'label' => 'VirusTotal API key',
            'value' => pm_Settings::get('virustotal_api_key'),
            'required' => true,
            'validators' => [
                ['NotEmpty', true],
            ],
        ]);

        $form->addControlButtons([
            'cancelLink' => pm_Context::getModulesListUrl(),
        ]);

        if ($this->getRequest()->isPost() && $form->isValid($this->getRequest()->getPost())) {

            pm_Settings::set('virustotal_enabled', $form->getValue('virustotal_enabled'));
            pm_Settings::set('virustotal_api_key', $form->getValue('virustotal_api_key'));

            $this->_status->addMessage('info', 'Settings was successfully saved.');
            $this->_helper->json(['redirect' => pm_Context::getBaseUrl()]);
        }

        $this->view->form = $form;
    }
    
    private function _getDomainsReportList() 
    {
        $admin_report = json_decode(pm_Settings::get('admin_report'), true);
        $i = 0;
        $data = [];
        foreach ($admin_report['domains'] as $domain) {
            $i++;
            
            $data[$i] = [
                'column-1' => $i,
                'column-2' => $domain['domain']['name'],
                'column-3' => $domain['virustotal_positives'] . ' / ' . $domain['virustotal_total'],
                'column-4' => '<a target="_blank" href="' . $domain['virustotal_domain_info_url'] . '">VirusTotal Report</a>',
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
