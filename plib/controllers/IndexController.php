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
        // Default action will be settingsAction
        if (!pm_Settings::get('virustotal_enabled')) {
            $this->_forward('settings');
            return;
        }

        $this->_forward('report');
    }

    public function reportAction()
    {
        // Default action will be settingsAction
        if (!pm_Settings::get('virustotal_enabled')) {
            $this->_forward('settings');
            return;
        }

        $list = $this->_getDomainsReportList();
        //var_dump($list);
        // List object for pm_View_Helper_RenderList
        $this->view->list = new pm_View_List_Simple($this->view, $this->_request, []);

    }
    
    public function settingsAction() 
    {
        $this->view->help_tip = "You can obtain API key after register on <a target='_blank' href='https://virustotal.com/'>https://virustotal.com/</a>";
        $this->view->debug = print_r(json_encode($this->_getDomainsReportList()), 1);
        // Init form here
        $form = new pm_Form_Simple();

        $form->addElement('checkbox', 'virustotal_enabled', [
            'label' => 'Virustotal Enabled',
            'value' => pm_Settings::get('virustotal_enabled'),
        ]);

        $form->addElement('text', 'virustotal_api_key', [
            'label' => 'VirusTotal API key',
            'value' => pm_Settings::get('virustotal_api_key'),
            'description' => 'You can obtain API key after register on <a target="_blank" href="https://virustotal.com/">https://virustotal.com/</a>',
            'required' => true,
            'validators' => [
                ['NotEmpty', true],
            ],
        ]);

        $form->addControlButtons([
            'cancelLink' => pm_Context::getModulesListUrl(),
        ]);

        if ($this->getRequest()->isPost() && $form->isValid($this->getRequest()->getPost())) {
            // Form proccessing here
            pm_Settings::set('virustotal_enabled', $form->getValue('virustotal_enabled'));
            pm_Settings::set('virustotal_api_key', $form->getValue('virustotal_api_key'));

            $this->_status->addMessage('info', 'Settings was successfully saved.');
            $this->_helper->json(['redirect' => pm_Context::getBaseUrl()]);
        }

        $this->view->form = $form;
    }
    
    private function _getDomainsReportList() 
    {
        return Modules_PleskExtensionsVirustotal_Helper::getDomains();
    }

}
