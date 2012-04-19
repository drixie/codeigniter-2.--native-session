<?php

class MY_Session extends CI_Session {

    public function __construct() {
        if (!isset($_SESSION)) {
            session_start();
        }

        return parent::__construct();
    }

    // --------------------------------------------------------------------

    /**
     * Write the session cookie
     *
     * @access	public
     * @return	void
     */
    function _set_cookie($cookie_data = NULL) {
        if (is_null($cookie_data)) {
            $cookie_data = $this->userdata;
        }

        // Serialize the userdata for the cookie
        $cookie_data = $this->_serialize($cookie_data);

        if ($this->sess_encrypt_cookie == TRUE) {
            $cookie_data = $this->CI->encrypt->encode($cookie_data);
        } else {
            // if encryption is not used, we provide an md5 hash to prevent userside tampering
            $cookie_data = $cookie_data . md5($cookie_data . $this->encryption_key);
        }

        $expire = ($this->sess_expire_on_close === TRUE) ? 0 : $this->sess_expiration + time();


        $_SESSION[$this->sess_cookie_name] = $cookie_data;
    }

    /**
     * Destroy the current session
     *
     * @access	public
     * @return	void
     */
    function sess_destroy() {
        // Kill the session DB row
        if ($this->sess_use_database === TRUE AND isset($this->userdata['session_id'])) {
            $this->CI->db->where('session_id', $this->userdata['session_id']);
            $this->CI->db->delete($this->sess_table_name);
        }


        $_SESSION[$this->sess_cookie_name] = addslashes(serialize(array()));
    }

    // --------------------------------------------------------------------

    /**
     * Fetch the current session data if it exists
     *
     * @access	public
     * @return	bool
     */
    function sess_read() {

        $session = isset($_SESSION[$this->sess_cookie_name]) ? $_SESSION[$this->sess_cookie_name] : FALSE;


        // No cookie?  Goodbye cruel world!...
        if ($session === FALSE) {
            log_message('debug', 'A session cookie was not found.');
            return FALSE;
        }

        // Decrypt the cookie data
        if ($this->sess_encrypt_cookie == TRUE) {
            $session = $this->CI->encrypt->decode($session);
        } else {
            // encryption was not used, so we need to check the md5 hash
            $hash = substr($session, strlen($session) - 32); // get last 32 chars
            $session = substr($session, 0, strlen($session) - 32);

            // Does the md5 hash match?  This is to prevent manipulation of session data in userspace
            if ($hash !== md5($session . $this->encryption_key)) {
                log_message('error', 'The session cookie data did not match what was expected. This could be a possible hacking attempt.');
                $this->sess_destroy();
                return FALSE;
            }
        }

        // Unserialize the session array
        $session = $this->_unserialize($session);

        // Is the session data we unserialized an array with the correct format?
        if (!is_array($session) OR !isset($session['session_id']) OR !isset($session['ip_address']) OR !isset($session['user_agent']) OR !isset($session['last_activity'])) {
            $this->sess_destroy();
            return FALSE;
        }

        // Is the session current?
        if (($session['last_activity'] + $this->sess_expiration) < $this->now) {
            $this->sess_destroy();
            return FALSE;
        }

        // Does the IP Match?
        if ($this->sess_match_ip == TRUE AND $session['ip_address'] != $this->CI->input->ip_address()) {
            $this->sess_destroy();
            return FALSE;
        }

        // Does the User Agent Match?
        if ($this->sess_match_useragent == TRUE AND trim($session['user_agent']) != trim(substr($this->CI->input->user_agent(), 0, 120))) {
            $this->sess_destroy();
            return FALSE;
        }

        // Is there a corresponding session in the DB?
        if ($this->sess_use_database === TRUE) {
            $this->CI->db->where('session_id', $session['session_id']);

            if ($this->sess_match_ip == TRUE) {
                $this->CI->db->where('ip_address', $session['ip_address']);
            }

            if ($this->sess_match_useragent == TRUE) {
                $this->CI->db->where('user_agent', $session['user_agent']);
            }

            $query = $this->CI->db->get($this->sess_table_name);

            // No result?  Kill it!
            if ($query->num_rows() == 0) {
                $this->sess_destroy();
                return FALSE;
            }

            // Is there custom data?  If so, add it to the main session array
            $row = $query->row();
            if (isset($row->user_data) AND $row->user_data != '') {
                $custom_data = $this->_unserialize($row->user_data);

                if (is_array($custom_data)) {
                    foreach ($custom_data as $key => $val) {
                        $session[$key] = $val;
                    }
                }
            }
        }

        // Session is valid!
        $this->userdata = $session;
        unset($session);

        return TRUE;
    }

}