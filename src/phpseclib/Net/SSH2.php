<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace PhpSecLib\Net;

/**
 * Pure-PHP implementation of SSHv2.
 *
 * PHP versions 4 and 5
 *
 * Here are some examples of how to use this library:
 * <code>
 * <?php
 *    include('Net/SSH2.php');
 *
 *    $ssh = new SSH2('www.domain.tld');
 *    if (!$ssh->login('username', 'password')) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->exec('pwd');
 *    echo $ssh->exec('ls -la');
 * ?>
 * </code>
 *
 * <code>
 * <?php
 *    include('Crypt/RSA.php');
 *    include('Net/SSH2.php');
 *
 *    $key = new RSA();
 *    //$key->setPassword('whatever');
 *    $key->loadKey(file_get_contents('privatekey'));
 *
 *    $ssh = new SSH2('www.domain.tld');
 *    if (!$ssh->login('username', $key)) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->read('username@username:~$');
 *    $ssh->write("ls -la\n");
 *    echo $ssh->read('username@username:~$');
 * ?>
 * </code>
 *
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @category   Net
 * @package    SSH2
 * @author     Jim Wigginton <terrafrost@php.net>
 * @copyright  MMVII Jim Wigginton
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       http://phpseclib.sourceforge.net
 */
use PhpSecLib\Crypt\Blowfish;
use PhpSecLib\Crypt\DES;
use PhpSecLib\Crypt\Hash;
use PhpSecLib\Crypt\Random;
use PhpSecLib\Crypt\RC4;
use PhpSecLib\Crypt\Rijndael;
use PhpSecLib\Crypt\RSA;
use PhpSecLib\Crypt\TripleDES;
use PhpSecLib\Crypt\Twofish;
use PhpSecLib\Math\BigInteger;
use PhpSecLib\Net\SSH2\ChannelOpenFailureReasons;
use PhpSecLib\Net\SSH2\DisconnectReasons;
use PhpSecLib\Net\SSH2\Messages;
use PhpSecLib\Net\SSH2\TerminalModes;

/**
 * Pure-PHP implementation of SSHv2.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class SSH2 {
    /**#@+
     * Execution Bitmap Masks
     *
     * @see SSH2::bitmap
     * @access private
     */
    const SSH2_MASK_CONSTRUCTOR=   0x00000001;
    const SSH2_MASK_LOGIN_REQ=     0x00000002;
    const SSH2_MASK_LOGIN=         0x00000004;
    const SSH2_MASK_SHELL=         0x00000008;
    const SSH2_MASK_WINDOW_ADJUST= 0X00000010;
    /**#@-*/

    /**#@+
     * Channel constants
     *
     * RFC4254 refers not to client and server channels but rather to sender and recipient channels.  we don't refer
     * to them in that way because RFC4254 toggles the meaning. the client sends a SSH_MSG_CHANNEL_OPEN message with
     * a sender channel and the server sends a SSH_MSG_CHANNEL_OPEN_CONFIRMATION in response, with a sender and a
     * recepient channel.  at first glance, you might conclude that SSH_MSG_CHANNEL_OPEN_CONFIRMATION's sender channel
     * would be the same thing as SSH_MSG_CHANNEL_OPEN's sender channel, but it's not, per this snipet:
     *     The 'recipient channel' is the channel number given in the original
     *     open request, and 'sender channel' is the channel number allocated by
     *     the other side.
     *
     * @see SSH2::_send_channel_packet()
     * @see SSH2::_get_channel_packet()
     * @access private
     */
    const SSH2_CHANNEL_EXEC= 0; // PuTTy uses 0x100
    const SSH2_CHANNEL_SHELL=1;
    /**#@-*/

    /**#@+
     * @access public
     * @see SSH2::getLog()
     */
    /**
     * Returns the message numbers
     */
    const SSH2_LOG_SIMPLE=  1;
    /**
     * Returns the message content
     */
    const SSH2_LOG_COMPLEX= 2;
    /**
     * Outputs the content real-time
     */
    const SSH2_LOG_REALTIME= 3;
    /**
     * Dumps the content real-time to a file
     */
    const SSH2_LOG_REALTIME_FILE= 4;
    /**#@-*/

    /**#@+
     * @access public
     * @see SSH2::read()
     */
    /**
     * Returns when a string matching $expect exactly is found
     */
    const SSH2_READ_SIMPLE=  1;
    /**
     * Returns when a string matching the regular expression $expect is found
     */
    const SSH2_READ_REGEX= 2;
    /**
     * Make sure that the log never gets larger than this
     */
    const SSH2_LOG_MAX_SIZE= 1048576; // 1024 * 1024
    /**#@-*/

    /**
     * The SSH identifier
     *
     * @var String
     * @access private
     */
    private $identifier = 'SSH-2.0-phpseclib_0.3';

    /**
     * The Socket Object
     *
     * @var Object
     * @access private
     */
    private $fsock;

    /**
     * Execution Bitmap
     *
     * The bits that are set represent functions that have been called already.  This is used to determine
     * if a requisite function has been successfully executed.  If not, an error should be thrown.
     *
     * @var Integer
     * @access private
     */
    private $bitmap = 0;

    /**
     * Error information
     *
     * @see SSH2::getErrors()
     * @see SSH2::getLastError()
     * @var String
     * @access private
     */
    private $errors = array();

    /**
     * Server Identifier
     *
     * @see SSH2::getServerIdentification()
     * @var String
     * @access private
     */
    private $server_identifier = '';

    /**
     * Key Exchange Algorithms
     *
     * @see SSH2::getKexAlgorithims()
     * @var Array
     * @access private
     */
    private $kex_algorithms;

    /**
     * Server Host Key Algorithms
     *
     * @see SSH2::getServerHostKeyAlgorithms()
     * @var Array
     * @access private
     */
    private $server_host_key_algorithms;

    /**
     * Encryption Algorithms: Client to Server
     *
     * @see SSH2::getEncryptionAlgorithmsClient2Server()
     * @var Array
     * @access private
     */
    private $encryption_algorithms_client_to_server;

    /**
     * Encryption Algorithms: Server to Client
     *
     * @see SSH2::getEncryptionAlgorithmsServer2Client()
     * @var Array
     * @access private
     */
    private $encryption_algorithms_server_to_client;

    /**
     * MAC Algorithms: Client to Server
     *
     * @see SSH2::getMACAlgorithmsClient2Server()
     * @var Array
     * @access private
     */
    private $mac_algorithms_client_to_server;

    /**
     * MAC Algorithms: Server to Client
     *
     * @see SSH2::getMACAlgorithmsServer2Client()
     * @var Array
     * @access private
     */
    private $mac_algorithms_server_to_client;

    /**
     * Compression Algorithms: Client to Server
     *
     * @see SSH2::getCompressionAlgorithmsClient2Server()
     * @var Array
     * @access private
     */
    private $compression_algorithms_client_to_server;

    /**
     * Compression Algorithms: Server to Client
     *
     * @see SSH2::getCompressionAlgorithmsServer2Client()
     * @var Array
     * @access private
     */
    private $compression_algorithms_server_to_client;

    /**
     * Languages: Server to Client
     *
     * @see SSH2::getLanguagesServer2Client()
     * @var Array
     * @access private
     */
    private $languages_server_to_client;

    /**
     * Languages: Client to Server
     *
     * @see SSH2::getLanguagesClient2Server()
     * @var Array
     * @access private
     */
    private $languages_client_to_server;

    /**
     * Block Size for Server to Client Encryption
     *
     * "Note that the length of the concatenation of 'packet_length',
     *  'padding_length', 'payload', and 'random padding' MUST be a multiple
     *  of the cipher block size or 8, whichever is larger.  This constraint
     *  MUST be enforced, even when using stream ciphers."
     *
     *  -- http://tools.ietf.org/html/rfc4253#section-6
     *
     * @see SSH2::__construct()
     * @see SSH2::_send_binary_packet()
     * @var Integer
     * @access private
     */
    private $encrypt_block_size = 8;

    /**
     * Block Size for Client to Server Encryption
     *
     * @see SSH2::__construct()
     * @see SSH2::_get_binary_packet()
     * @var Integer
     */
    private $decrypt_block_size = 8;

    /**
     * Server to Client Encryption Object
     *
     * @see SSH2::_get_binary_packet()
     * @var Object
     */
    private $decrypt = false;

    /**
     * Client to Server Encryption Object
     *
     * @see SSH2::_send_binary_packet()
     * @var Object
     */
    private $encrypt = false;

    /**
     * Client to Server HMAC Object
     *
     * @see SSH2::_send_binary_packet()
     * @var Object
     */
    private $hmac_create = false;

    /**
     * Server to Client HMAC Object
     *
     * @see SSH2::_get_binary_packet()
     * @var Object
     */
    private $hmac_check = false;

    /**
     * Size of server to client HMAC
     *
     * We need to know how big the HMAC will be for the server to client direction so that we know how many bytes to read.
     * For the client to server side, the HMAC object will make the HMAC as long as it needs to be.  All we need to do is
     * append it.
     *
     * @see SSH2::_get_binary_packet()
     * @var Integer
     */
    private $hmac_size = false;

    /**
     * Server Public Host Key
     *
     * @see SSH2::getServerPublicHostKey()
     * @var String
     */
    private $server_public_host_key;

    /**
     * Session identifer
     *
     * "The exchange hash H from the first key exchange is additionally
     *  used as the session identifier, which is a unique identifier for
     *  this connection."
     *
     *  -- http://tools.ietf.org/html/rfc4253#section-7.2
     *
     * @see SSH2::_key_exchange(key_exchange
     * @var String
     */
    private $session_id = false;

    /**
     * Exchange hash
     *
     * The current exchange hash
     *
     * @see SSH2::_key_exchange(key_exchange
     * @var String
     */
    private $exchange_hash = false;

    /**
     * Message Numbers
     *
     * @see SSH2::__construct()
     * @var Array
     */
    private $message_numbers = array();


    /**
     * Send Sequence Number
     *
     * See 'Section 6.4.  Data Integrity' of rfc4253 for more info.
     *
     * @see SSH2::_send_binary_packet()
     * @var Integer
     */
    private $send_seq_no = 0;

    /**
     * Get Sequence Number
     *
     * See 'Section 6.4.  Data Integrity' of rfc4253 for more info.
     *
     * @see SSH2::_get_binary_packet()
     * @var Integer
     * @access private
     */
    private $get_seq_no = 0;

    /**
     * Server Channels
     *
     * Maps client channels to server channels
     *
     * @see SSH2::_get_channel_packet()
     * @see SSH2::exec()
     * @var Array
     * @access private
     */
    private $server_channels = array();

    /**
     * Channel Buffers
     *
     * If a client requests a packet from one channel but receives two packets from another those packets should
     * be placed in a buffer
     *
     * @see SSH2::_get_channel_packet()
     * @see SSH2::exec()
     * @var Array
     * @access private
     */
    private $channel_buffers = array();

    /**
     * Channel Status
     *
     * Contains the type of the last sent message
     *
     * @see SSH2::_get_channel_packet()
     * @var Array
     * @access private
     */
    private $channel_status = array();

    /**
     * Packet Size
     *
     * Maximum packet size indexed by channel
     *
     * @see SSH2::_send_channel_packet()
     * @var Array
     * @access private
     */
    private $packet_size_client_to_server = array();

    /**
     * Message Number Log
     *
     * @see SSH2::getLog()
     * @var Array
     * @access private
     */
    private $message_number_log = array();

    /**
     * Message Log
     *
     * @see SSH2::getLog()
     * @var Array
     * @access private
     */
    private $message_log = array();

    /**
     * The Window Size
     *
     * Bytes the other party can send before it must wait for the window to be adjusted (0x7FFFFFFF = 2GB)
     *
     * @var Integer
     * @see SSH2::_send_channel_packet()
     * @see SSH2::exec()
     * @access private
     */
    private $window_size = 0x7FFFFFFF;

    /**
     * Window size, server to client
     *
     * Window size indexed by channel
     *
     * @see SSH2::_send_channel_packet()
     * @var Array
     * @access private
     */
    private $window_size_server_to_client = array();

    /**
     * Window size, client to server
     *
     * Window size indexed by channel
     *
     * @see SSH2::_get_channel_packet()
     * @var Array
     * @access private
     */
    private $window_size_client_to_server = array();

    /**
     * Server signature
     *
     * Verified against $this->session_id
     *
     * @see SSH2::getServerPublicHostKey()
     * @var String
     * @access private
     */
    private $signature = '';

    /**
     * Server signature format
     *
     * ssh-rsa or ssh-dss.
     *
     * @see SSH2::getServerPublicHostKey()
     * @var String
     * @access private
     */
    private $signature_format = '';

    /**
     * Interactive Buffer
     *
     * @see SSH2::read()
     * @var Array
     * @access private
     */
    private $interactiveBuffer = '';

    /**
     * Current log size
     *
     * Should never exceed self::SSH2_LOG_MAX_SIZE
     *
     * @see SSH2::_send_binary_packet()
     * @see SSH2::_get_binary_packet()
     * @var Integer
     * @access private
     */
    private $log_size;

    /**
     * Timeout
     *
     * @see SSH2::setTimeout()
     * @access private
     */
    private $timeout;

    /**
     * Current Timeout
     *
     * @see SSH2::_get_channel_packet()
     * @access private
     */
    private $curTimeout;

    /**
     * Real-time log file pointer
     *
     * @see SSH2::_append_log()
     * @var Resource
     * @access private
     */
    private $realtime_log_file;

    /**
     * Real-time log file size
     *
     * @see SSH2::_append_log()
     * @var Integer
     * @access private
     */
    private $realtime_log_size;

    /**
     * Has the signature been validated?
     *
     * @see SSH2::getServerPublicHostKey()
     * @var Boolean
     * @access private
     */
    private $signature_validated = false;

    /**
     * Real-time log file wrap boolean
     *
     * @see SSH2::_append_log()
     * @access private
     */
    private $realtime_log_wrap;

    /**
     * Flag to suppress stderr from output
     *
     * @see SSH2::enableQuietMode()
     * @access private
     */
    private $quiet_mode = false;

    /**
     * Time of first network activity
     *
     * @access private
     */
    private $last_packet;

    /**
     * Exit status returned from ssh if any
     *
     * @var Integer
     * @access private
     */
    private $exit_status;

    /**
     * Flag to request a PTY when using exec()
     *
     * @see SSH2::enablePTY()
     * @access private
     */
    private $request_pty = false;

    /**
     * Flag set while exec() is running when using enablePTY()
     *
     * @access private
     */
    private $in_request_pty_exec = false;

    /**
     * Contents of stdError
     *
     * @access private
     */
    private $stdErrorLog;

    /**
     * The Last Interactive Response
     *
     * @see SSH2::_keyboard_interactive_process()
     * @access private
     */
    private $last_interactive_response = '';

    /**
     * Keyboard Interactive Request / Responses
     *
     * @see SSH2::_keyboard_interactive_process()
     * @access private
     */
    private $keyboard_requests_responses = array();

    /**
     * Banner Message
     *
     * Quoting from the RFC, "in some jurisdictions, sending a warning message before
     * authentication may be relevant for getting legal protection."
     *
     * @see SSH2::_filter()
     * @see SSH2::getBannerMessage()
     * @access private
     */
    private $banner_message = '';

    /**
     * Did read() timeout or return normally?
     *
     * @see SSH2::isTimeout
     * @access private
     */
    private $is_timeout = false;


    private $decompress;

    /**
     * Connects to an SSHv2 server
     *
     * @param String $host
     * @param optional Integer $port
     * @param optional Integer $timeout
     *
     * @Todo: maybe split this to a connect method ?
     */
    public function __construct($host, $port = 22, $timeout = 10)
    {
        $this->last_packet = microtime(true);
        $start = microtime(true);
        $this->fsock = @fsockopen($host, $port, $errno, $errstr, $timeout);
        if (!$this->fsock) {
            user_error(rtrim("Cannot connect to $host. Error $errno. $errstr"));
        }
        $elapsed = microtime(true) - $start;

        $timeout-= $elapsed;

        if ($timeout <= 0) {
            user_error(rtrim("Cannot connect to $host. Timeout error"));
        }

        $read = array($this->fsock);
        $write = $except = NULL;

        $sec = floor($timeout);
        $usec = 1000000 * ($timeout - $sec);

        // on windows this returns a "Warning: Invalid CRT parameters detected" error
        // the !count() is done as a workaround for <https://bugs.php.net/42682>
        if (!@stream_select($read, $write, $except, $sec, $usec) && !count($read)) {
            user_error(rtrim("Cannot connect to $host. Banner timeout"));
        }

        /* According to the SSH2 specs,

          "The server MAY send other lines of data before sending the version
           string.  Each line SHOULD be terminated by a Carriage Return and Line
           Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
           in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
           MUST be able to process such lines." */
        $temp = '';
        $extra = '';
        $matches = null;
        while (!feof($this->fsock) && !preg_match('#^SSH-(\d\.\d+)#', $temp, $matches)) {
            if (substr($temp, -2) == "\r\n") {
                $extra.= $temp;
                $temp = '';
            }
            $temp.= fgets($this->fsock, 255);
        }

        if (feof($this->fsock)) {
            user_error('Connection closed by server');
            return false;
        }

        $ext = array();
        if (extension_loaded('mcrypt')) {
            $ext[] = 'mcrypt';
        }
        if (extension_loaded('gmp')) {
            $ext[] = 'gmp';
        } else if (extension_loaded('bcmath')) {
            $ext[] = 'bcmath';
        }

        if (!empty($ext)) {
            $this->identifier.= ' (' . implode(', ', $ext) . ')';
        }

        if (defined('SSH2_LOGGING')) {
            $this->_append_log('<-', $extra . $temp);
            $this->_append_log('->', $this->identifier . "\r\n");
        }

        $this->server_identifier = trim($temp, "\r\n");
        if (strlen($extra)) {
            $this->errors[] = utf8_decode($extra);
        }

        if ($matches[1] != '1.99' && $matches[1] != '2.0') {
            user_error("Cannot connect to SSH $matches[1] servers");
        }

        fputs($this->fsock, $this->identifier . "\r\n");

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server');
        }

        if (ord($response[0]) != Messages::NET_SSH2_MSG_KEXINIT) {
            user_error('Expected SSH_MSG_KEXINIT');
        }

        if ($this->key_exchange($response)) {
            $this->bitmap = self::SSH2_MASK_CONSTRUCTOR;
        }

    }

    /**
     * Key Exchange
     *
     * @param String $kexinit_payload_server
     * @return bool
     */
    private function key_exchange($kexinit_payload_server)
    {
        static $kex_algorithms = array(
            'diffie-hellman-group1-sha1', // REQUIRED
            'diffie-hellman-group14-sha1' // REQUIRED
        );

        static $server_host_key_algorithms = array(
            'ssh-rsa', // RECOMMENDED  sign   Raw RSA Key
            'ssh-dss' // REQUIRED     sign   Raw DSS Key
        );

        static $encryption_algorithms = false;
        if ($encryption_algorithms === false) {
            $encryption_algorithms = array(
                // from <http://tools.ietf.org/html/rfc4345#section-4>:
                'arcfour256',
                'arcfour128',

                'arcfour', // OPTIONAL          the ARCFOUR stream cipher with a 128-bit key

                // CTR modes from <http://tools.ietf.org/html/rfc4344#section-4>:
                'aes128-ctr', // RECOMMENDED       AES (Rijndael) in SDCTR mode, with 128-bit key
                'aes192-ctr', // RECOMMENDED       AES with 192-bit key
                'aes256-ctr', // RECOMMENDED       AES with 256-bit key

                'twofish128-ctr', // OPTIONAL          Twofish in SDCTR mode, with 128-bit key
                'twofish192-ctr', // OPTIONAL          Twofish with 192-bit key
                'twofish256-ctr', // OPTIONAL          Twofish with 256-bit key

                'aes128-cbc', // RECOMMENDED       AES with a 128-bit key
                'aes192-cbc', // OPTIONAL          AES with a 192-bit key
                'aes256-cbc', // OPTIONAL          AES in CBC mode, with a 256-bit key

                'twofish128-cbc', // OPTIONAL          Twofish with a 128-bit key
                'twofish192-cbc', // OPTIONAL          Twofish with a 192-bit key
                'twofish256-cbc',
                'twofish-cbc', // OPTIONAL          alias for "twofish256-cbc"
                //                   (this is being retained for historical reasons)

                'blowfish-ctr', // OPTIONAL          Blowfish in SDCTR mode

                'blowfish-cbc', // OPTIONAL          Blowfish in CBC mode

                '3des-ctr', // RECOMMENDED       Three-key 3DES in SDCTR mode

                '3des-cbc', // REQUIRED          three-key 3DES in CBC mode
                'none' // OPTIONAL          no encryption; NOT RECOMMENDED
            );
        }

        static $mac_algorithms = array(
            'hmac-sha1-96', // RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
            'hmac-sha1', // REQUIRED        HMAC-SHA1 (digest length = key length = 20)
            'hmac-md5-96', // OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
            'hmac-md5', // OPTIONAL        HMAC-MD5 (digest length = key length = 16)
            'none' // OPTIONAL        no MAC; NOT RECOMMENDED
        );

        static $compression_algorithms = array(
            'none' // REQUIRED        no compression
            //'zlib' // OPTIONAL        ZLIB (LZ77) compression
        );

        // some SSH servers have buggy implementations of some of the above algorithms
        switch ($this->server_identifier) {
            case 'SSH-2.0-SSHD':
                $mac_algorithms = array_values(array_diff(
                    $mac_algorithms,
                    array('hmac-sha1-96', 'hmac-md5-96')
                ));
        }

        static $str_kex_algorithms, $str_server_host_key_algorithms,
        $encryption_algorithms_server_to_client, $mac_algorithms_server_to_client, $compression_algorithms_server_to_client,
        $encryption_algorithms_client_to_server, $mac_algorithms_client_to_server, $compression_algorithms_client_to_server;

        if (empty($str_kex_algorithms)) {
            $str_kex_algorithms = implode(',', $kex_algorithms);
            $str_server_host_key_algorithms = implode(',', $server_host_key_algorithms);
            $encryption_algorithms_server_to_client = $encryption_algorithms_client_to_server = implode(',', $encryption_algorithms);
            $mac_algorithms_server_to_client = $mac_algorithms_client_to_server = implode(',', $mac_algorithms);
            $compression_algorithms_server_to_client = $compression_algorithms_client_to_server = implode(',', $compression_algorithms);
        }

        $client_cookie = Random::crypt_random_string(16);

        $response = $kexinit_payload_server;
        $this->_string_shift($response, 1); // skip past the message number (it should be SSH_MSG_KEXINIT)
        $server_cookie = $this->_string_shift($response, 16);

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->kex_algorithms = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->server_host_key_algorithms = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->encryption_algorithms_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->encryption_algorithms_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->mac_algorithms_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->mac_algorithms_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->compression_algorithms_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->compression_algorithms_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->languages_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->languages_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

        $first_kex_packet_follows = unpack('Cfirst_kex_packet_follows', $this->_string_shift($response, 1))['first_kex_packet_follows'] != 0;

        // the sending of SSH2_MSG_KEXINIT could go in one of two places.  this is the second place.
        $kexinit_payload_client = pack('Ca*Na*Na*Na*Na*Na*Na*Na*Na*Na*Na*CN',
            Messages::NET_SSH2_MSG_KEXINIT, $client_cookie, strlen($str_kex_algorithms), $str_kex_algorithms,
            strlen($str_server_host_key_algorithms), $str_server_host_key_algorithms, strlen($encryption_algorithms_client_to_server),
            $encryption_algorithms_client_to_server, strlen($encryption_algorithms_server_to_client), $encryption_algorithms_server_to_client,
            strlen($mac_algorithms_client_to_server), $mac_algorithms_client_to_server, strlen($mac_algorithms_server_to_client),
            $mac_algorithms_server_to_client, strlen($compression_algorithms_client_to_server), $compression_algorithms_client_to_server,
            strlen($compression_algorithms_server_to_client), $compression_algorithms_server_to_client, 0, '', 0, '',
            0, 0
        );

        if (!$this->_send_binary_packet($kexinit_payload_client)) {
            return false;
        }
        // here ends the second place.

        // we need to decide upon the symmetric encryption algorithms before we do the diffie-hellman key exchange
        for ($i = 0; $i < count($encryption_algorithms) && !in_array($encryption_algorithms[$i], $this->encryption_algorithms_server_to_client); $i++) ;
        if ($i == count($encryption_algorithms)) {
            user_error('No compatible server to client encryption algorithms found');
            return $this->_disconnect(DisconnectReasons::KEY_EXCHANGE_FAILED);
        }

        // we don't initialize any crypto-objects, yet - we do that, later. for now, we need the lengths to make the
        // diffie-hellman key exchange as fast as possible
        $decrypt = $encryption_algorithms[$i];
        $decryptKeyLength = 0;
        switch ($decrypt) {
            case '3des-cbc':
            case '3des-ctr':
                $decryptKeyLength = 24; // eg. 192 / 8
                break;
            case 'aes256-cbc':
            case 'aes256-ctr':
            case 'twofish-cbc':
            case 'twofish256-cbc':
            case 'twofish256-ctr':
                $decryptKeyLength = 32; // eg. 256 / 8
                break;
            case 'aes192-cbc':
            case 'aes192-ctr':
            case 'twofish192-cbc':
            case 'twofish192-ctr':
                $decryptKeyLength = 24; // eg. 192 / 8
                break;
            case 'aes128-cbc':
            case 'aes128-ctr':
            case 'twofish128-cbc':
            case 'twofish128-ctr':
            case 'blowfish-cbc':
            case 'blowfish-ctr':
                $decryptKeyLength = 16; // eg. 128 / 8
                break;
            case 'arcfour':
            case 'arcfour128':
                $decryptKeyLength = 16; // eg. 128 / 8
                break;
            case 'arcfour256':
                $decryptKeyLength = 32; // eg. 128 / 8
                break;
            case 'none';
                $decryptKeyLength = 0;
        }

        for ($i = 0; $i < count($encryption_algorithms) && !in_array($encryption_algorithms[$i], $this->encryption_algorithms_client_to_server); $i++) ;
        if ($i == count($encryption_algorithms)) {
            user_error('No compatible client to server encryption algorithms found');
            return $this->_disconnect(DisconnectReasons::KEY_EXCHANGE_FAILED);
        }

        $encrypt = $encryption_algorithms[$i];
        $encryptKeyLength = 0;
        switch ($encrypt) {
            case '3des-cbc':
            case '3des-ctr':
                $encryptKeyLength = 24;
                break;
            case 'aes256-cbc':
            case 'aes256-ctr':
            case 'twofish-cbc':
            case 'twofish256-cbc':
            case 'twofish256-ctr':
                $encryptKeyLength = 32;
                break;
            case 'aes192-cbc':
            case 'aes192-ctr':
            case 'twofish192-cbc':
            case 'twofish192-ctr':
                $encryptKeyLength = 24;
                break;
            case 'aes128-cbc':
            case 'aes128-ctr':
            case 'twofish128-cbc':
            case 'twofish128-ctr':
            case 'blowfish-cbc':
            case 'blowfish-ctr':
                $encryptKeyLength = 16;
                break;
            case 'arcfour':
            case 'arcfour128':
                $encryptKeyLength = 16;
                break;
            case 'arcfour256':
                $encryptKeyLength = 32;
                break;
            case 'none';
                $encryptKeyLength = 0;
        }

        $keyLength = $decryptKeyLength > $encryptKeyLength ? $decryptKeyLength : $encryptKeyLength;

        // through diffie-hellman key exchange a symmetric key is obtained
        for ($i = 0; $i < count($kex_algorithms) && !in_array($kex_algorithms[$i], $this->kex_algorithms); $i++) ;
        if ($i == count($kex_algorithms)) {
            user_error('No compatible key exchange algorithms found');
            return $this->_disconnect(DisconnectReasons::KEY_EXCHANGE_FAILED);
        }

        $prime = null;
        switch ($kex_algorithms[$i]) {
            // see http://tools.ietf.org/html/rfc2409#section-6.2 and 
            // http://tools.ietf.org/html/rfc2412, appendex E
            case 'diffie-hellman-group1-sha1':
                $prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
                    '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
                    '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
                    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF';
                break;
            // see http://tools.ietf.org/html/rfc3526#section-3
            case 'diffie-hellman-group14-sha1':
                $prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
                    '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
                    '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
                    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' .
                    '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' .
                    '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' .
                    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' .
                    '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF';
                break;
        }

        // For both diffie-hellman-group1-sha1 and diffie-hellman-group14-sha1
        // the generator field element is 2 (decimal) and the hash function is sha1.
        $g = new BigInteger(2);
        $prime = new BigInteger($prime, 16);
        $kexHash = new Hash('sha1');
        //$q = $p->bitwise_rightShift(1);

        /* To increase the speed of the key exchange, both client and server may
           reduce the size of their private exponents.  It should be at least
           twice as long as the key material that is generated from the shared
           secret.  For more details, see the paper by van Oorschot and Wiener
           [VAN-OORSCHOT].

           -- http://tools.ietf.org/html/rfc4419#section-6.2 */
        $one = new BigInteger(1);
        $keyLength = min($keyLength, $kexHash->getLength());
        $max = $one->bitwise_leftShift(16 * $keyLength)->subtract($one); // 2 * 8 * $keyLength

        $x = $one->random($one, $max);
        $e = $g->modPow($x, $prime);

        $eBytes = $e->toBytes(true);
        $data = pack('CNa*', Messages::NET_SSH2_MSG_KEXDH_INIT, strlen($eBytes), $eBytes);

        if (!$this->_send_binary_packet($data)) {
            user_error('Connection closed by server');
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }
        $type = unpack('Ctype', $this->_string_shift($response, 1))['type'];

        if ($type != Messages::NET_SSH2_MSG_KEXDH_REPLY) {
            user_error('Expected SSH_MSG_KEXDH_REPLY');
            return false;
        }

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->server_public_host_key = $server_public_host_key = $this->_string_shift($response, $temp['length']);

        $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
        $public_key_format = $this->_string_shift($server_public_host_key, $temp['length']);

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $fBytes = $this->_string_shift($response, $temp['length']);
        $f = new BigInteger($fBytes, -256);

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->signature = $this->_string_shift($response, $temp['length']);

        $temp = unpack('Nlength', $this->_string_shift($this->signature, 4));
        $this->signature_format = $this->_string_shift($this->signature, $temp['length']);

        $key = $f->modPow($x, $prime);
        $keyBytes = $key->toBytes(true);

        $this->exchange_hash = pack('Na*Na*Na*Na*Na*Na*Na*Na*',
            strlen($this->identifier), $this->identifier, strlen($this->server_identifier), $this->server_identifier,
            strlen($kexinit_payload_client), $kexinit_payload_client, strlen($kexinit_payload_server),
            $kexinit_payload_server, strlen($this->server_public_host_key), $this->server_public_host_key, strlen($eBytes),
            $eBytes, strlen($fBytes), $fBytes, strlen($keyBytes), $keyBytes
        );

        $this->exchange_hash = $kexHash->hash($this->exchange_hash);

        if ($this->session_id === false) {
            $this->session_id = $this->exchange_hash;
        }

        for ($i = 0; $i < count($server_host_key_algorithms) && !in_array($server_host_key_algorithms[$i], $this->server_host_key_algorithms); $i++) ;
        if ($i == count($server_host_key_algorithms)) {
            user_error('No compatible server host key algorithms found');
            return $this->_disconnect(DisconnectReasons::KEY_EXCHANGE_FAILED);
        }

        if ($public_key_format != $server_host_key_algorithms[$i] || $this->signature_format != $server_host_key_algorithms[$i]) {
            user_error('Server Host Key Algorithm Mismatch');
            return $this->_disconnect(DisconnectReasons::KEY_EXCHANGE_FAILED);
        }

        $packet = pack('C',
            Messages::NET_SSH2_MSG_NEWKEYS
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();

        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        if ($type != Messages::NET_SSH2_MSG_NEWKEYS) {
            user_error('Expected SSH_MSG_NEWKEYS');
            return false;
        }

        switch ($encrypt) {
            case '3des-cbc':
                $this->encrypt = new TripleDES();
                // $this->encrypt_block_size = 64 / 8 == the default
                break;
            case '3des-ctr':
                $this->encrypt = new TripleDES(DES::CRYPT_DES_MODE_CTR);
                // $this->encrypt_block_size = 64 / 8 == the default
                break;
            case 'aes256-cbc':
            case 'aes192-cbc':
            case 'aes128-cbc':
                $this->encrypt = new Rijndael();
                $this->encrypt_block_size = 16; // eg. 128 / 8
                break;
            case 'aes256-ctr':
            case 'aes192-ctr':
            case 'aes128-ctr':
                $this->encrypt = new Rijndael(Rijndael::CRYPT_RIJNDAEL_MODE_CTR);
                $this->encrypt_block_size = 16; // eg. 128 / 8
                break;
            case 'blowfish-cbc':
                $this->encrypt = new Blowfish();
                $this->encrypt_block_size = 8;
                break;
            case 'blowfish-ctr':
                $this->encrypt = new Blowfish(Blowfish::CRYPT_BLOWFISH_MODE_CTR);
                $this->encrypt_block_size = 8;
                break;
            case 'twofish128-cbc':
            case 'twofish192-cbc':
            case 'twofish256-cbc':
            case 'twofish-cbc':
                $this->encrypt = new Twofish();
                $this->encrypt_block_size = 16;
                break;
            case 'twofish128-ctr':
            case 'twofish192-ctr':
            case 'twofish256-ctr':
                $this->encrypt = new Twofish(Twofish::CRYPT_TWOFISH_MODE_CTR);
                $this->encrypt_block_size = 16;
                break;
            case 'arcfour':
            case 'arcfour128':
            case 'arcfour256':
                $this->encrypt = new RC4();
                break;
            case 'none';
                //$this->encrypt = new Crypt_Null();
        }

        switch ($decrypt) {
            case '3des-cbc':
                $this->decrypt = new TripleDES();
                break;
            case '3des-ctr':
                $this->decrypt = new TripleDES(DES::CRYPT_DES_MODE_CTR);
                break;
            case 'aes256-cbc':
            case 'aes192-cbc':
            case 'aes128-cbc':
                $this->decrypt = new Rijndael();
                $this->decrypt_block_size = 16;
                break;
            case 'aes256-ctr':
            case 'aes192-ctr':
            case 'aes128-ctr':
                $this->decrypt = new Rijndael(Rijndael::CRYPT_RIJNDAEL_MODE_CTR);
                $this->decrypt_block_size = 16;
                break;
            case 'blowfish-cbc':
                $this->decrypt = new Blowfish();
                $this->decrypt_block_size = 8;
                break;
            case 'blowfish-ctr':
                $this->decrypt = new Blowfish(Blowfish::CRYPT_BLOWFISH_MODE_CTR);
                $this->decrypt_block_size = 8;
                break;
            case 'twofish128-cbc':
            case 'twofish192-cbc':
            case 'twofish256-cbc':
            case 'twofish-cbc':
                $this->decrypt = new Twofish();
                $this->decrypt_block_size = 16;
                break;
            case 'twofish128-ctr':
            case 'twofish192-ctr':
            case 'twofish256-ctr':
                $this->decrypt = new Twofish(Twofish::CRYPT_TWOFISH_MODE_CTR);
                $this->decrypt_block_size = 16;
                break;
            case 'arcfour':
            case 'arcfour128':
            case 'arcfour256':
                $this->decrypt = new RC4();
                break;
            case 'none';
                //$this->decrypt = new Crypt_Null();
        }

        $keyBytes = pack('Na*', strlen($keyBytes), $keyBytes);

        if ($this->encrypt) {
            $this->encrypt->enableContinuousBuffer();
            $this->encrypt->disablePadding();

            $iv = $kexHash->hash($keyBytes . $this->exchange_hash . 'A' . $this->session_id);
            while ($this->encrypt_block_size > strlen($iv)) {
                $iv .= $kexHash->hash($keyBytes . $this->exchange_hash . $iv);
            }
            $this->encrypt->setIV(substr($iv, 0, $this->encrypt_block_size));

            $key = $kexHash->hash($keyBytes . $this->exchange_hash . 'C' . $this->session_id);
            while ($encryptKeyLength > strlen($key)) {
                $key .= $kexHash->hash($keyBytes . $this->exchange_hash . $key);
            }
            $this->encrypt->setKey(substr($key, 0, $encryptKeyLength));
        }

        if ($this->decrypt) {
            $this->decrypt->enableContinuousBuffer();
            $this->decrypt->disablePadding();

            $iv = $kexHash->hash($keyBytes . $this->exchange_hash . 'B' . $this->session_id);
            while ($this->decrypt_block_size > strlen($iv)) {
                $iv .= $kexHash->hash($keyBytes . $this->exchange_hash . $iv);
            }
            $this->decrypt->setIV(substr($iv, 0, $this->decrypt_block_size));

            $key = $kexHash->hash($keyBytes . $this->exchange_hash . 'D' . $this->session_id);
            while ($decryptKeyLength > strlen($key)) {
                $key .= $kexHash->hash($keyBytes . $this->exchange_hash . $key);
            }
            $this->decrypt->setKey(substr($key, 0, $decryptKeyLength));
        }

        /* The "arcfour128" algorithm is the RC4 cipher, as described in
           [SCHNEIER], using a 128-bit key.  The first 1536 bytes of keystream
           generated by the cipher MUST be discarded, and the first byte of the
           first encrypted packet MUST be encrypted using the 1537th byte of
           keystream.

           -- http://tools.ietf.org/html/rfc4345#section-4 */
        if ($encrypt == 'arcfour128' || $encrypt == 'arcfour256') {
            $this->encrypt->encrypt(str_repeat("\0", 1536));
        }
        if ($decrypt == 'arcfour128' || $decrypt == 'arcfour256') {
            $this->decrypt->decrypt(str_repeat("\0", 1536));
        }

        for ($i = 0; $i < count($mac_algorithms) && !in_array($mac_algorithms[$i], $this->mac_algorithms_client_to_server); $i++) ;
        if ($i == count($mac_algorithms)) {
            user_error('No compatible client to server message authentication algorithms found');
            return $this->_disconnect(DisconnectReasons::KEY_EXCHANGE_FAILED);
        }

        $createKeyLength = 0; // ie. $mac_algorithms[$i] == 'none'
        switch ($mac_algorithms[$i]) {
            case 'hmac-sha1':
                $this->hmac_create = new Hash('sha1');
                $createKeyLength = 20;
                break;
            case 'hmac-sha1-96':
                $this->hmac_create = new Hash('sha1-96');
                $createKeyLength = 20;
                break;
            case 'hmac-md5':
                $this->hmac_create = new Hash('md5');
                $createKeyLength = 16;
                break;
            case 'hmac-md5-96':
                $this->hmac_create = new Hash('md5-96');
                $createKeyLength = 16;
        }

        for ($i = 0; $i < count($mac_algorithms) && !in_array($mac_algorithms[$i], $this->mac_algorithms_server_to_client); $i++) ;
        if ($i == count($mac_algorithms)) {
            user_error('No compatible server to client message authentication algorithms found');
            return $this->_disconnect(DisconnectReasons::KEY_EXCHANGE_FAILED);
        }

        $checkKeyLength = 0;
        $this->hmac_size = 0;
        switch ($mac_algorithms[$i]) {
            case 'hmac-sha1':
                $this->hmac_check = new Hash('sha1');
                $checkKeyLength = 20;
                $this->hmac_size = 20;
                break;
            case 'hmac-sha1-96':
                $this->hmac_check = new Hash('sha1-96');
                $checkKeyLength = 20;
                $this->hmac_size = 12;
                break;
            case 'hmac-md5':
                $this->hmac_check = new Hash('md5');
                $checkKeyLength = 16;
                $this->hmac_size = 16;
                break;
            case 'hmac-md5-96':
                $this->hmac_check = new Hash('md5-96');
                $checkKeyLength = 16;
                $this->hmac_size = 12;
        }

        $key = $kexHash->hash($keyBytes . $this->exchange_hash . 'E' . $this->session_id);
        while ($createKeyLength > strlen($key)) {
            $key .= $kexHash->hash($keyBytes . $this->exchange_hash . $key);
        }
        $this->hmac_create->setKey(substr($key, 0, $createKeyLength));

        $key = $kexHash->hash($keyBytes . $this->exchange_hash . 'F' . $this->session_id);
        while ($checkKeyLength > strlen($key)) {
            $key .= $kexHash->hash($keyBytes . $this->exchange_hash . $key);
        }
        $this->hmac_check->setKey(substr($key, 0, $checkKeyLength));

        for ($i = 0; $i < count($compression_algorithms) && !in_array($compression_algorithms[$i], $this->compression_algorithms_server_to_client); $i++) ;
        if ($i == count($compression_algorithms)) {
            user_error('No compatible server to client compression algorithms found');
            return $this->_disconnect(DisconnectReasons::KEY_EXCHANGE_FAILED);
        }
        $this->decompress = $compression_algorithms[$i] == 'zlib';

        for ($i = 0; $i < count($compression_algorithms) && !in_array($compression_algorithms[$i], $this->compression_algorithms_client_to_server); $i++) ;
        if ($i == count($compression_algorithms)) {
            user_error('No compatible client to server compression algorithms found');
            return $this->_disconnect(DisconnectReasons::KEY_EXCHANGE_FAILED);
        }
        $this->compress = $compression_algorithms[$i] == 'zlib';

        return true;
    }

    /**
     * Login
     *
     * The $password parameter can be a plaintext password, a RSA object or an array
     *
     * @param String $username
     * @param Mixed $password
     * @param Mixed $...
     * @return Boolean
     * @see login_helper
     *
     * @Todo: remove the magic 2 parameter here
     */
    public function login($username)
    {
        $args = array_slice(func_get_args(), 1);
        if (empty($args)) {
            return $this->login_helper($username);
        }

        foreach ($args as $arg) {
            if ($this->login_helper($username, $arg)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Login Helper
     *
     * @param String $username
     * @param optional String $password
     * @return Boolean
     * @internal It might be worthwhile, at some point, to protect against {@link http://tools.ietf.org/html/rfc4251#section-9.3.9 traffic analysis}
     *           by sending dummy SSH_MSG_IGNORE messages.
     */
    private function login_helper($username, $password = null)
    {
        if (!($this->bitmap & self::SSH2_MASK_CONSTRUCTOR)) {
            return false;
        }

        if (!($this->bitmap & self::SSH2_MASK_LOGIN_REQ)) {
            $packet = pack('CNa*',
                Messages::NET_SSH2_MSG_SERVICE_REQUEST, strlen('ssh-userauth'), 'ssh-userauth'
            );

            if (!$this->_send_binary_packet($packet)) {
                return false;
            }

            $response = $this->_get_binary_packet();
            if ($response === false) {
                user_error('Connection closed by server');
                return false;
            }

            $type = unpack('Ctype', $this->_string_shift($response, 1))['type'];

            if ($type != Messages::NET_SSH2_MSG_SERVICE_ACCEPT) {
                user_error('Expected SSH_MSG_SERVICE_ACCEPT');
                return false;
            }
            $this->bitmap |= self::SSH2_MASK_LOGIN_REQ;
        }

        if (strlen($this->last_interactive_response)) {
            return !is_string($password) && !is_array($password) ? false : $this->_keyboard_interactive_process($password);
        }

        // although PHP5's get_class() preserves the case, PHP4's does not
        if (is_object($password) && strtolower(get_class($password)) == 'RSA') {
            return $this->_privatekey_login($username, $password);
        }

        if (is_array($password)) {
            if ($this->_keyboard_interactive_login($username, $password)) {
                $this->bitmap |= self::SSH2_MASK_LOGIN;
                return true;
            }
            return false;
        }

        if (!isset($password)) {
            $packet = pack('CNa*Na*Na*',
                Messages::NET_SSH2_MSG_USERAUTH_REQUEST, strlen($username), $username, strlen('ssh-connection'), 'ssh-connection',
                strlen('none'), 'none'
            );

            if (!$this->_send_binary_packet($packet)) {
                return false;
            }

            $response = $this->_get_binary_packet();
            if ($response === false) {
                user_error('Connection closed by server');
                return false;
            }

            $type = unpack('Ctype', $this->_string_shift($response, 1))['type'];

            switch ($type) {
                case Messages::NET_SSH2_MSG_USERAUTH_SUCCESS:
                    $this->bitmap |= self::SSH2_MASK_LOGIN;
                    return true;
                //case SSH2_MSG_USERAUTH_FAILURE:
                default:
                    return false;
            }
        }

        $packet = pack('CNa*Na*Na*CNa*',
            Messages::NET_SSH2_MSG_USERAUTH_REQUEST, strlen($username), $username, strlen('ssh-connection'), 'ssh-connection',
            strlen('password'), 'password', 0, strlen($password), $password
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        // remove the username and password from the last logged packet
        if (defined('SSH2_LOGGING') && SSH2_LOGGING == self::SSH2_LOG_COMPLEX) {
            $packet = pack('CNa*Na*Na*CNa*',
                Messages::NET_SSH2_MSG_USERAUTH_REQUEST, strlen('username'), 'username', strlen('ssh-connection'), 'ssh-connection',
                strlen('password'), 'password', 0, strlen('password'), 'password'
            );
            $this->message_log[count($this->message_log) - 1] = $packet;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }

        $type = unpack('Ctype', $this->_string_shift($response, 1))['type'];

        switch ($type) {
            case Messages::NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ: // in theory, the password can be changed
                if (defined('SSH2_LOGGING')) {
                    $this->message_number_log[count($this->message_number_log) - 1] = 'SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ';
                }
                $length = unpack('Nlength', $this->_string_shift($response, 4))['length'];
                $this->errors[] = 'SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: ' . utf8_decode($this->_string_shift($response, $length));
                return $this->_disconnect(DisconnectReasons::AUTH_CANCELLED_BY_USER);
            case Messages::NET_SSH2_MSG_USERAUTH_FAILURE:
                // can we use keyboard-interactive authentication?  if not then either the login is bad or the server employees
                // multi-factor authentication
                $result = unpack('Nlength', $this->_string_shift($response, 4));
                $auth_methods = explode(',', $this->_string_shift($response, $result['length']));
                extract(unpack('Cpartial_success', $this->_string_shift($response, 1)));
                $partial_success = $result['partial_success'] != 0;

                if (!$partial_success && in_array('keyboard-interactive', $auth_methods)) {
                    if ($this->_keyboard_interactive_login($username, $password)) {
                        $this->bitmap |= self::SSH2_MASK_LOGIN;
                        return true;
                    }
                    return false;
                }
                return false;
            case Messages::NET_SSH2_MSG_USERAUTH_SUCCESS:
                $this->bitmap |= self::SSH2_MASK_LOGIN;
                return true;
        }

        return false;
    }

    /**
     * Login via keyboard-interactive authentication
     *
     * See {@link http://tools.ietf.org/html/rfc4256 RFC4256} for details.  This is not a full-featured keyboard-interactive authenticator.
     *
     * @param String $username
     * @param String $password
     * @return Boolean
     * @access private
     */
    function _keyboard_interactive_login($username, $password)
    {
        $packet = pack('CNa*Na*Na*Na*Na*', 
            Messages::NET_SSH2_MSG_USERAUTH_REQUEST, strlen($username), $username, strlen('ssh-connection'), 'ssh-connection',
            strlen('keyboard-interactive'), 'keyboard-interactive', 0, '', 0, ''
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        return $this->_keyboard_interactive_process($password);
    }

    /**
     * Handle the keyboard-interactive requests / responses.
     *
     * @param String $responses...
     * @return Boolean
     * @access private
     */
    function _keyboard_interactive_process()
    {
        $responses = func_get_args();
        $orig = null;

        if (strlen($this->last_interactive_response)) {
            $response = $this->last_interactive_response;
        } else {
            $orig = $response = $this->_get_binary_packet();
            if ($response === false) {
                user_error('Connection closed by server');
                return false;
            }
        }

        $type = unpack('Ctype', $this->_string_shift($response, 1))['type'];

        switch ($type) {
            case Messages::NET_SSH2_MSG_USERAUTH_INFO_REQUEST:
                $length = unpack('Nlength', $this->_string_shift($response, 4))['length'];
                $this->_string_shift($response, $length); // name; may be empty
                $length = unpack('Nlength', $this->_string_shift($response, 4))['length'];
                $this->_string_shift($response, $length); // instruction; may be empty
                $length = unpack('Nlength', $this->_string_shift($response, 4))['length'];
                $this->_string_shift($response, $length); // language tag; may be empty
                $numPrompts = unpack('Nnum_prompts', $this->_string_shift($response, 4))['num_prompts'];

                for ($i = 0; $i < count($responses); $i++) {
                    if (is_array($responses[$i])) {
                        foreach ($responses[$i] as $key => $value) {
                            $this->keyboard_requests_responses[$key] = $value;
                        }
                        unset($responses[$i]);
                    }
                }
                $responses = array_values($responses);

                if (isset($this->keyboard_requests_responses)) {
                    for ($i = 0; $i < $numPrompts; $i++) {
                        $length = unpack('Nlength', $this->_string_shift($response, 4))['length'];
                        // prompt - ie. "Password: "; must not be empty
                        $prompt = $this->_string_shift($response, $length);
                        //$echo = $this->_string_shift($response) != chr(0);
                        foreach ($this->keyboard_requests_responses as $key => $value) {
                            if (substr($prompt, 0, strlen($key)) == $key) {
                                $responses[] = $value;
                                break;
                            }
                        }
                    }
                }

                // see http://tools.ietf.org/html/rfc4256#section-3.2
                if (strlen($this->last_interactive_response)) {
                    $this->last_interactive_response = '';
                } else if (defined('SSH2_LOGGING')) {
                    $this->message_number_log[count($this->message_number_log) - 1] = str_replace(
                        'UNKNOWN',
                        'SSH2_MSG_USERAUTH_INFO_REQUEST',
                        $this->message_number_log[count($this->message_number_log) - 1]
                    );
                }

                if (!count($responses) && $numPrompts) {
                    $this->last_interactive_response = $orig;
                    $this->bitmap |= self::SSH_MASK_LOGIN_INTERACTIVE;
                    return false;
                }

                /*
                   After obtaining the requested information from the user, the client
                   MUST respond with an SSH_MSG_USERAUTH_INFO_RESPONSE message.
                */
                // see http://tools.ietf.org/html/rfc4256#section-3.4
                $packet = $logged = pack('CN', Messages::NET_SSH2_MSG_USERAUTH_INFO_RESPONSE, count($responses));
                for ($i = 0; $i < count($responses); $i++) {
                    $packet.= pack('Na*', strlen($responses[$i]), $responses[$i]);
                    $logged.= pack('Na*', strlen('dummy-answer'), 'dummy-answer');
                }

                if (!$this->_send_binary_packet($packet)) {
                    return false;
                }

                if (defined('SSH2_LOGGING')) {
                    $this->message_number_log[count($this->message_number_log) - 1] = str_replace(
                        'UNKNOWN',
                        'SSH2_MSG_USERAUTH_INFO_RESPONSE',
                        $this->message_number_log[count($this->message_number_log) - 1]
                    );
                    $this->message_log[count($this->message_log) - 1] = $logged;
                }

                /*
                   After receiving the response, the server MUST send either an
                   SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE, or another
                   SSH_MSG_USERAUTH_INFO_REQUEST message.
                */
                // maybe PhpSecLib should force close the connection after x request / responses?  unless something like that is done
                // there could be an infinite loop of request / responses.
                return $this->_keyboard_interactive_process();
            case Messages::NET_SSH2_MSG_USERAUTH_SUCCESS:
                return true;
            case Messages::NET_SSH2_MSG_USERAUTH_FAILURE:
                return false;
        }

        return false;
    }

    /**
     * Login with an RSA private key
     *
     * @param String $username
     * @param $privateKey
     * @return Boolean
     * @internal It might be worthwhile, at some point, to protect against {@link http://tools.ietf.org/html/rfc4251#section-9.3.9 traffic analysis}
     *           by sending dummy SSH_MSG_IGNORE messages.
     */
    private function _privatekey_login($username, RSA $privateKey)
    {
        // see http://tools.ietf.org/html/rfc4253#page-15
        $publicKey = $privateKey->getPublicKey(RSA::PUBLIC_FORMAT_RAW);
        if ($publicKey === false) {
            return false;
        }

        $publicKey = array(
            'e' => $publicKey['e']->toBytes(true),
            'n' => $publicKey['n']->toBytes(true)
        );
        $publicKey = pack('Na*Na*Na*',
            strlen('ssh-rsa'), 'ssh-rsa', strlen($publicKey['e']), $publicKey['e'], strlen($publicKey['n']), $publicKey['n']
        );

        $part1 = pack('CNa*Na*Na*',
            Messages::NET_SSH2_MSG_USERAUTH_REQUEST, strlen($username), $username, strlen('ssh-connection'), 'ssh-connection',
            strlen('publickey'), 'publickey'
        );
        $part2 = pack('Na*Na*', strlen('ssh-rsa'), 'ssh-rsa', strlen($publicKey), $publicKey);

        $packet = $part1 . chr(0) . $part2;
        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }

        $type = unpack('Ctype', $this->_string_shift($response, 1))['type'];
        switch ($type) {
            case Messages::NET_SSH2_MSG_USERAUTH_FAILURE:
                $length = unpack('Nlength', $this->_string_shift($response, 4))['length'];
                $this->errors[] = 'SSH_MSG_USERAUTH_FAILURE: ' . $this->_string_shift($response, $length);
                return false;
            case Messages::NET_SSH2_MSG_USERAUTH_PK_OK:
                // we'll just take it on faith that the public key blob and the public key algorithm name are as
                // they should be
                if (defined('SSH2_LOGGING')) {
                    $this->message_number_log[count($this->message_number_log) - 1] = str_replace(
                        'UNKNOWN',
                        'SSH2_MSG_USERAUTH_PK_OK',
                        $this->message_number_log[count($this->message_number_log) - 1]
                    );
                }
        }

        $packet = $part1 . chr(1) . $part2;
        $privateKey->setSignatureMode(RSA::SIGNATURE_PKCS1);
        $signature = $privateKey->sign(pack('Na*a*', strlen($this->session_id), $this->session_id, $packet));
        $signature = pack('Na*Na*', strlen('ssh-rsa'), 'ssh-rsa', strlen($signature), $signature);
        $packet.= pack('Na*', strlen($signature), $signature);

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        switch ($type) {
            case Messages::NET_SSH2_MSG_USERAUTH_FAILURE:
                // either the login is bad or the server employs multi-factor authentication
                return false;
            case Messages::NET_SSH2_MSG_USERAUTH_SUCCESS:
                $this->bitmap |= self::SSH2_MASK_LOGIN;
                return true;
        }

        return false;
    }

    /**
     * Set Timeout
     *
     * $ssh->exec('ping 127.0.0.1'); on a Linux host will never return and will run indefinitely.  setTimeout() makes it so it'll timeout.
     * Setting $timeout to false or 0 will mean there is no timeout.
     *
     * @param Mixed $timeout
     * @access public
     */
    function setTimeout($timeout)
    {
        $this->timeout = $this->curTimeout = $timeout;
    }

    /**
     * Get the output from stdError
     * 
     * @access public
     */
    function getStdError()
    {
        return $this->stdErrorLog;
    }

    /**
     * Execute Command
     *
     * If $block is set to false then SSH2::_get_channel_packet(self::SSH2_CHANNEL_EXEC) will need to be called manually.
     * In all likelihood, this is not a feature you want to be taking advantage of.
     *
     * @param String $command
     * @param null $callback
     * @return String
     */
    public function exec($command, $callback = null)
    {
        $this->curTimeout = $this->timeout;
        $this->is_timeout = false;
        $this->stdErrorLog = '';

        if (!($this->bitmap & self::SSH2_MASK_LOGIN)) {
            return false;
        }

        // RFC4254 defines the (client) window size as "bytes the other party can send before it must wait for the window to
        // be adjusted".  0x7FFFFFFF is, at 2GB, the max size.  technically, it should probably be decremented, but, 
        // honestly, if you're transfering more than 2GB, you probably shouldn't be using PhpSecLib, anyway.
        // see http://tools.ietf.org/html/rfc4254#section-5.2 for more info
        $this->window_size_server_to_client[self::SSH2_CHANNEL_EXEC] = 0x7FFFFFFF;
        // 0x8000 is the maximum max packet size, per http://tools.ietf.org/html/rfc4253#section-6.1, although since PuTTy
        // uses 0x4000, that's what will be used here, as well.
        $packet_size = 0x4000;

        $packet = pack('CNa*N3',
            Messages::NET_SSH2_MSG_CHANNEL_OPEN, strlen('session'), 'session', self::SSH2_CHANNEL_EXEC, $this->window_size_server_to_client[self::SSH2_CHANNEL_EXEC], $packet_size);

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[self::SSH2_CHANNEL_EXEC] = Messages::NET_SSH2_MSG_CHANNEL_OPEN;

        $response = $this->_get_channel_packet(self::SSH2_CHANNEL_EXEC);
        if ($response === false) {
            return false;
        }

        if ($this->request_pty === true) {
            $terminal_modes = pack('C', TerminalModes::NET_SSH2_TTY_OP_END);
            $packet = pack('CNNa*CNa*N5a*',
                Messages::NET_SSH2_MSG_CHANNEL_REQUEST, $this->server_channels[self::SSH2_CHANNEL_EXEC], strlen('pty-req'), 'pty-req', 1, strlen('vt100'), 'vt100',
                80, 24, 0, 0, strlen($terminal_modes), $terminal_modes);

            if (!$this->_send_binary_packet($packet)) {
                return false;
            }
            $response = $this->_get_binary_packet();
            if ($response === false) {
                user_error('Connection closed by server');
                return false;
            }

            list(, $type) = unpack('C', $this->_string_shift($response, 1));

            switch ($type) {
                case Messages::NET_SSH2_MSG_CHANNEL_SUCCESS:
                    break;
                case Messages::NET_SSH2_MSG_CHANNEL_FAILURE:
                default:
                    user_error('Unable to request pseudo-terminal');
                    return $this->_disconnect(DisconnectReasons::BY_APPLICATION);
            }
            $this->in_request_pty_exec = true;
        }

        // sending a pty-req SSH_MSG_CHANNEL_REQUEST message is unnecessary and, in fact, in most cases, slows things
        // down.  the one place where it might be desirable is if you're doing something like SSH2::exec('ping localhost &').
        // with a pty-req SSH_MSG_CHANNEL_REQUEST, exec() will return immediately and the ping process will then
        // then immediately terminate.  without such a request exec() will loop indefinitely.  the ping process won't end but
        // neither will your script.

        // although, in theory, the size of SSH_MSG_CHANNEL_REQUEST could exceed the maximum packet size established by
        // SSH_MSG_CHANNEL_OPEN_CONFIRMATION, RFC4254#section-5.1 states that the "maximum packet size" refers to the 
        // "maximum size of an individual data packet". ie. SSH_MSG_CHANNEL_DATA.  RFC4254#section-5.2 corroborates.
        $packet = pack('CNNa*CNa*',
            Messages::NET_SSH2_MSG_CHANNEL_REQUEST, $this->server_channels[self::SSH2_CHANNEL_EXEC], strlen('exec'), 'exec', 1, strlen($command), $command);
        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[self::SSH2_CHANNEL_EXEC] = Messages::NET_SSH2_MSG_CHANNEL_REQUEST;

        $response = $this->_get_channel_packet(self::SSH2_CHANNEL_EXEC);
        if ($response === false) {
            return false;
        }

        $this->channel_status[self::SSH2_CHANNEL_EXEC] = Messages::NET_SSH2_MSG_CHANNEL_DATA;

        if ($callback === false || $this->in_request_pty_exec) {
            return true;
        }

        $output = '';
        while (true) {
            $temp = $this->_get_channel_packet(self::SSH2_CHANNEL_EXEC);
            switch (true) {
                case $temp === true:
                    return is_callable($callback) ? true : $output;
                case $temp === false:
                    return false;
                default:
                    if (is_callable($callback)) {
                        $callback($temp);
                    } else {
                        $output.= $temp;
                    }
            }
        }
    }

    /**
     * Creates an interactive shell
     *
     * @see SSH2::read()
     * @see SSH2::write()
     * @return Boolean
     * @access private
     */
    private function initShell()
    {
        if ($this->in_request_pty_exec === true) {
            return true;
        }

        $this->window_size_server_to_client[self::SSH2_CHANNEL_SHELL] = 0x7FFFFFFF;
        $packet_size = 0x4000;

        $packet = pack('CNa*N3',
            Messages::NET_SSH2_MSG_CHANNEL_OPEN, strlen('session'), 'session', self::SSH2_CHANNEL_SHELL, $this->window_size_server_to_client[self::SSH2_CHANNEL_SHELL], $packet_size);

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[self::SSH2_CHANNEL_SHELL] =Messages::NET_SSH2_MSG_CHANNEL_OPEN;

        $response = $this->_get_channel_packet(self::SSH2_CHANNEL_SHELL);
        if ($response === false) {
            return false;
        }

        $terminal_modes = pack('C', TerminalModes::NET_SSH2_TTY_OP_END);
        $packet = pack('CNNa*CNa*N5a*',
            Messages::NET_SSH2_MSG_CHANNEL_REQUEST, $this->server_channels[self::SSH2_CHANNEL_SHELL], strlen('pty-req'), 'pty-req', 1, strlen('vt100'), 'vt100',
            80, 24, 0, 0, strlen($terminal_modes), $terminal_modes);

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }

        list(, $type) = unpack('C', $this->_string_shift($response, 1));

        switch ($type) {
            case Messages::NET_SSH2_MSG_CHANNEL_SUCCESS:
                break;
            case Messages::NET_SSH2_MSG_CHANNEL_FAILURE:
            default:
                user_error('Unable to request pseudo-terminal');
                return $this->_disconnect(DisconnectReasons::BY_APPLICATION);
        }

        $packet = pack('CNNa*C',
            Messages::NET_SSH2_MSG_CHANNEL_REQUEST, $this->server_channels[self::SSH2_CHANNEL_SHELL], strlen('shell'), 'shell', 1);
        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[self::SSH2_CHANNEL_SHELL] = Messages::NET_SSH2_MSG_CHANNEL_REQUEST;

        $response = $this->_get_channel_packet(self::SSH2_CHANNEL_SHELL);
        if ($response === false) {
            return false;
        }

        $this->channel_status[self::SSH2_CHANNEL_SHELL] = Messages::NET_SSH2_MSG_CHANNEL_DATA;

        $this->bitmap |= self::SSH2_MASK_SHELL;

        return true;
    }

    /**
     * Returns the output of an interactive shell
     *
     * Returns when there's a match for $expect, which can take the form of a string literal or,
     * if $mode == self::SSH2_READ_REGEX, a regular expression.
     *
     * @see SSH2::read()
     * @param String $expect
     * @param Integer $mode
     * @return String
     */
    public function read($expect = '', $mode = self::SSH2_READ_SIMPLE)
    {
        $this->curTimeout = $this->timeout;
        $this->is_timeout = false;

        if (!($this->bitmap & self::SSH2_MASK_LOGIN)) {
            user_error('Operation disallowed prior to login()');
            return false;
        }

        if (!($this->bitmap & self::SSH2_MASK_SHELL) && !$this->initShell()) {
            user_error('Unable to initiate an interactive shell session');
            return false;
        }

        $channel = $this->in_request_pty_exec ? self::SSH2_CHANNEL_EXEC : self::SSH2_CHANNEL_SHELL;

        $match = $expect;
        while (true) {
            if ($mode == self::SSH2_READ_REGEX) {
                preg_match($expect, $this->interactiveBuffer, $matches);
                $match = isset($matches[0]) ? $matches[0] : '';
            }
            $pos = strlen($match) ? strpos($this->interactiveBuffer, $match) : false;
            if ($pos !== false) {
                return $this->_string_shift($this->interactiveBuffer, $pos + strlen($match));
            }
            $response = $this->_get_channel_packet($channel);
            if (is_bool($response)) {
                $this->in_request_pty_exec = false;
                return $response ? $this->_string_shift($this->interactiveBuffer, strlen($this->interactiveBuffer)) : false;
            }

            $this->interactiveBuffer.= $response;
        }
    }

    /**
     * Inputs a command into an interactive shell.
     *
     * @see Net_SSH1::interactiveWrite()
     * @param String $cmd
     * @return Boolean
     */
    public function write($cmd)
    {
        if (!($this->bitmap & self::SSH2_MASK_LOGIN)) {
            user_error('Operation disallowed prior to login()');
            return false;
        }

        if (!($this->bitmap & self::SSH2_MASK_SHELL) && !$this->initShell()) {
            user_error('Unable to initiate an interactive shell session');
            return false;
        }

        $channel = $this->in_request_pty_exec ? self::SSH2_CHANNEL_EXEC : self::SSH2_CHANNEL_SHELL;
        return $this->_send_channel_packet($channel, $cmd);
    }

    /**
     * Closes a channel
     *
     * If read() timed out you might want to just close the channel and have it auto-restart on the next read() call
     *
     * @access public
     */
    function reset()
    {
        $channel = $this->in_request_pty_exec ? self::SSH2_CHANNEL_EXEC : self::SSH2_CHANNEL_SHELL;
        $this->_close_channel($channel);
    }

    /**
     * Did exec() or read() return because they timed out or because they encountered the end?
     *
     * @return boolean
     */
    public function isTimeout()
    {
        return $this->is_timeout;
    }

    /**
     * Disconnect
     */
    public function disconnect()
    {
        $this->_disconnect(DisconnectReasons::BY_APPLICATION);
        if (isset($this->realtime_log_file) && is_resource($this->realtime_log_file)) {
            fclose($this->realtime_log_file);
        }
    }

    public function __destruct()
    {
        $this->disconnect();
    }

    /**
     * Is the connection still active?
     */
    public function isConnected()
    {
        return $this->bitmap & self::SSH2_MASK_LOGIN;
    }

    /**
     * Gets Binary Packets
     *
     * See '6. Binary Packet Protocol' of rfc4253 for more info.
     *
     * @see SSH2::_send_binary_packet()
     * @return String
     */
    private function _get_binary_packet()
    {
        if (!is_resource($this->fsock) || feof($this->fsock)) {
            user_error('Connection closed prematurely');
            $this->bitmask = 0;
            return false;
        }

        $start = microtime(true); // http://php.net/microtime#61838
        $raw = fread($this->fsock, $this->decrypt_block_size);

        if (!strlen($raw)) {
            return '';
        }

        if ($this->decrypt !== false) {
            $raw = $this->decrypt->decrypt($raw);
        }
        if ($raw === false) {
            user_error('Unable to decrypt content');
            return false;
        }

        extract(unpack('Npacket_length/Cpadding_length', $this->_string_shift($raw, 5)));

        $remaining_length = $packet_length + 4 - $this->decrypt_block_size;

        // quoting <http://tools.ietf.org/html/rfc4253#section-6.1>,
        // "implementations SHOULD check that the packet length is reasonable"
        // PuTTY uses 0x9000 as the actual max packet size and so to shall we
        if ($remaining_length < -$this->decrypt_block_size || $remaining_length > 0x9000 || $remaining_length % $this->decrypt_block_size != 0) {
            user_error('Invalid size');
            return false;
        }

        $buffer = '';
        while ($remaining_length > 0) {
            $temp = fread($this->fsock, $remaining_length);
            $buffer.= $temp;
            $remaining_length-= strlen($temp);
        }
        $stop = microtime(true);
        if (strlen($buffer)) {
            $raw.= $this->decrypt !== false ? $this->decrypt->decrypt($buffer) : $buffer;
        }

        $payload = $this->_string_shift($raw, $packet_length - $padding_length - 1);
        $padding = $this->_string_shift($raw, $padding_length); // should leave $raw empty

        if ($this->hmac_check !== false) {
            $hmac = fread($this->fsock, $this->hmac_size);
            if ($hmac != $this->hmac_check->hash(pack('NNCa*', $this->get_seq_no, $packet_length, $padding_length, $payload . $padding))) {
                user_error('Invalid HMAC');
                return false;
            }
        }

        //if ($this->decompress) {
        //    $payload = gzinflate(substr($payload, 2));
        //}

        $this->get_seq_no++;

        if (defined('SSH2_LOGGING')) {
            $current = microtime(true);
            $message_number = isset($this->message_numbers[ord($payload[0])]) ? $this->message_numbers[ord($payload[0])] : 'UNKNOWN (' . ord($payload[0]) . ')';
            $message_number = '<- ' . $message_number .
                              ' (since last: ' . round($current - $this->last_packet, 4) . ', network: ' . round($stop - $start, 4) . 's)';
            $this->_append_log($message_number, $payload);
            $this->last_packet = $current;
        }

        return $this->_filter($payload);
    }

    /**
     * Filter Binary Packets
     *
     * Because some binary packets need to be ignored...
     *
     * @see SSH2::_get_binary_packet()
     * @param $payload
     * @return String
     */
    private function _filter($payload)
    {
        switch (ord($payload[0])) {
            case Messages::NET_SSH2_MSG_DISCONNECT:
                $this->_string_shift($payload, 1);
                extract(unpack('Nreason_code/Nlength', $this->_string_shift($payload, 8)));
                $this->errors[] = 'SSH_MSG_DISCONNECT: ' . $this->disconnect_reasons[$reason_code] . "\r\n" . utf8_decode($this->_string_shift($payload, $length)); // TODO: fix this
                $this->bitmask = 0;
                return false;
            case Messages::NET_SSH2_MSG_IGNORE:
                $payload = $this->_get_binary_packet();
                break;
            case Messages::NET_SSH2_MSG_DEBUG:
                $this->_string_shift($payload, 2);
                extract(unpack('Nlength', $this->_string_shift($payload, 4)));
                $this->errors[] = 'SSH_MSG_DEBUG: ' . utf8_decode($this->_string_shift($payload, $length));
                $payload = $this->_get_binary_packet();
                break;
            case Messages::NET_SSH2_MSG_UNIMPLEMENTED:
                return false;
            case Messages::NET_SSH2_MSG_KEXINIT:
                if ($this->session_id !== false) {
                    if (!$this->key_exchange($payload)) {
                        $this->bitmask = 0;
                        return false;
                    }
                    $payload = $this->_get_binary_packet();
                }
        }

        // see http://tools.ietf.org/html/rfc4252#section-5.4; only called when the encryption has been activated and when we haven't already logged in
        if (($this->bitmap & self::SSH2_MASK_CONSTRUCTOR) && !($this->bitmap & self::SSH2_MASK_LOGIN) && ord($payload[0]) == Messages::NET_SSH2_MSG_USERAUTH_BANNER) {
            $this->_string_shift($payload, 1);
            extract(unpack('Nlength', $this->_string_shift($payload, 4)));
            $this->banner_message = utf8_decode($this->_string_shift($payload, $length));
            $payload = $this->_get_binary_packet();
        }

        // only called when we've already logged in
        if (($this->bitmap & self::SSH2_MASK_CONSTRUCTOR) && ($this->bitmap & self::SSH2_MASK_LOGIN)) {
            switch (ord($payload[0])) {
                case Messages::NET_SSH2_MSG_GLOBAL_REQUEST: // see http://tools.ietf.org/html/rfc4254#section-4
                    $this->_string_shift($payload, 1);
                    extract(unpack('Nlength', $this->_string_shift($payload)));
                    $this->errors[] = 'SSH_MSG_GLOBAL_REQUEST: ' . utf8_decode($this->_string_shift($payload, $length));

                    if (!$this->_send_binary_packet(pack('C', Messages::NET_SSH2_MSG_REQUEST_FAILURE))) {
                        return $this->_disconnect(DisconnectReasons::BY_APPLICATION);
                    }

                    $payload = $this->_get_binary_packet();
                    break;
                case Messages::NET_SSH2_MSG_CHANNEL_OPEN: // see http://tools.ietf.org/html/rfc4254#section-5.1
                    $this->_string_shift($payload, 1);
                    extract(unpack('Nlength', $this->_string_shift($payload, 4)));
                    $this->errors[] = 'SSH_MSG_CHANNEL_OPEN: ' . utf8_decode($this->_string_shift($payload, $length));

                    $this->_string_shift($payload, 4); // skip over client channel
                    extract(unpack('Nserver_channel', $this->_string_shift($payload, 4)));

                    $packet = pack('CN3a*Na*',
                        Messages::NET_SSH2_MSG_REQUEST_FAILURE, $server_channel, ChannelOpenFailureReasons::NET_SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED, 0, '', 0, '');

                    if (!$this->_send_binary_packet($packet)) {
                        return $this->_disconnect(DisconnectReasons::BY_APPLICATION);
                    }

                    $payload = $this->_get_binary_packet();
                    break;
                case Messages::NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST:
                    $this->_string_shift($payload, 1);
                    extract(unpack('Nchannel', $this->_string_shift($payload, 4)));
                    extract(unpack('Nwindow_size', $this->_string_shift($payload, 4)));
                    $this->window_size_client_to_server[$channel] = $window_size;

                    $payload = ($this->bitmap & self::SSH2_MASK_WINDOW_ADJUST) ? true : $this->_get_binary_packet();

            }
        }

        return $payload;
    }

    /**
     * Enable Quiet Mode
     *
     * Suppress stderr from output
     */
    public function enableQuietMode()
    {
        $this->quiet_mode = true;
    }

    /**
     * Disable Quiet Mode
     *
     * Show stderr in output
     */
    public function disableQuietMode()
    {
        $this->quiet_mode = false;
    }

    /**
     * Enable request-pty when using exec()
     */
    public function enablePTY()
    {
        $this->request_pty = true;
    }

    /**
     * Disable request-pty when using exec()
     */
    public function disablePTY()
    {
        $this->request_pty = false;
    }

    /**
     * Gets channel data
     *
     * Returns the data as a string if it's available and false if not.
     *
     * @param $client_channel
     * @param bool $skip_extended
     * @return mixed
     */
    private function _get_channel_packet($client_channel, $skip_extended = false)
    {
        if (!empty($this->channel_buffers[$client_channel])) {
            return array_shift($this->channel_buffers[$client_channel]);
        }

        while (true) {
            if ($this->curTimeout) {
                if ($this->curTimeout < 0) {
                    $this->is_timeout = true;
                    return true;
                }

                $read = array($this->fsock);
                $write = $except = NULL;

                $start = microtime(true);
                $sec = floor($this->curTimeout);
                $usec = 1000000 * ($this->curTimeout - $sec);
                // on windows this returns a "Warning: Invalid CRT parameters detected" error
                if (!@stream_select($read, $write, $except, $sec, $usec) && !count($read)) {
                    $this->is_timeout = true;
                    return true;
                }
                $elapsed = microtime(true) - $start;
                $this->curTimeout-= $elapsed;
            }

            $response = $this->_get_binary_packet();
            if ($response === false) {
                user_error('Connection closed by server');
                return false;
            }
            if ($client_channel == -1 && $response === true) {
                return true;
            }
            if (!strlen($response)) {
                return '';
            }

            extract(unpack('Ctype/Nchannel', $this->_string_shift($response, 5)));

            // resize the window, if appropriate
            $this->window_size_server_to_client[$channel]-= strlen($response);
            if ($this->window_size_server_to_client[$channel] < 0) {
                $packet = pack('CNN', Messages::SSH2_MSG_CHANNEL_WINDOW_ADJUST, $this->server_channels[$channel], $this->window_size);
                if (!$this->_send_binary_packet($packet)) {
                    return false;
                }
                $this->window_size_server_to_client[$channel]+= $this->window_size;
            }

            switch ($this->channel_status[$channel]) {
                case Messages::NET_SSH2_MSG_CHANNEL_OPEN:
                    switch ($type) {
                        case Messages::NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
                            extract(unpack('Nserver_channel', $this->_string_shift($response, 4)));
                            $this->server_channels[$channel] = $server_channel;
                            extract(unpack('Nwindow_size', $this->_string_shift($response, 4)));
                            $this->window_size_client_to_server[$channel] = $window_size;
                            $temp = unpack('Npacket_size_client_to_server', $this->_string_shift($response, 4));
                            $this->packet_size_client_to_server[$channel] = $temp['packet_size_client_to_server'];
                            return $client_channel == $channel ? true : $this->_get_channel_packet($client_channel, $skip_extended);
                        //case SSH2_MSG_CHANNEL_OPEN_FAILURE:
                        default:
                            user_error('Unable to open channel');
                            return $this->_disconnect(DisconnectReasons::BY_APPLICATION);
                    }
                    break;
                case Messages::NET_SSH2_MSG_CHANNEL_REQUEST:
                    switch ($type) {
                        case Messages::NET_SSH2_MSG_CHANNEL_SUCCESS:
                            return true;
                        case Messages::NET_SSH2_MSG_CHANNEL_FAILURE:
                            return false;
                        default:
                            user_error('Unable to fulfill channel request');
                            return $this->_disconnect(DisconnectReasons::SSH2_DISCONNECT_BY_APPLICATION);
                    }
                case Messages::NET_SSH2_MSG_CHANNEL_CLOSE:
                    return $type == Messages::NET_SSH2_MSG_CHANNEL_CLOSE ? true : $this->_get_channel_packet($client_channel, $skip_extended);
            }

            // ie. $this->channel_status[$channel] == SSH2_MSG_CHANNEL_DATA

            switch ($type) {
                case Messages::NET_SSH2_MSG_CHANNEL_DATA:
                    /*
                    if ($channel == self::SSH2_CHANNEL_EXEC) {
                        // SCP requires null packets, such as this, be sent.  further, in the case of the ssh.com SSH server
                        // this actually seems to make things twice as fast.  more to the point, the message right after 
                        // SSH_MSG_CHANNEL_DATA (usually SSH_MSG_IGNORE) won't block for as long as it would have otherwise.
                        // in OpenSSH it slows things down but only by a couple thousandths of a second.
                        $this->_send_channel_packet($channel, chr(0));
                    }
                    */
                    extract(unpack('Nlength', $this->_string_shift($response, 4)));
                    $data = $this->_string_shift($response, $length);
                    if ($client_channel == $channel) {
                        return $data;
                    }
                    if (!isset($this->channel_buffers[$channel])) {
                        $this->channel_buffers[$channel] = array();
                    }
                    $this->channel_buffers[$channel][] = $data;
                    break;
                case Messages::NET_SSH2_MSG_CHANNEL_EXTENDED_DATA:
                    /*
                    if ($client_channel == self::SSH2_CHANNEL_EXEC) {
                        $this->_send_channel_packet($client_channel, chr(0));
                    }
                    */
                    // currently, there's only one possible value for $data_type_code: SSH2_EXTENDED_DATA_STDERR
                    extract(unpack('Ndata_type_code/Nlength', $this->_string_shift($response, 8)));
                    $data = $this->_string_shift($response, $length);
                    $this->stdErrorLog .= $data;
                    if ($skip_extended || $this->quiet_mode) {
                        break;
                    }
                    if ($client_channel == $channel) {
                        return $data;
                    }
                    if (!isset($this->channel_buffers[$channel])) {
                        $this->channel_buffers[$channel] = array();
                    }
                    $this->channel_buffers[$channel][] = $data;
                    break;
                case Messages::NET_SSH2_MSG_CHANNEL_REQUEST:
                    extract(unpack('Nlength', $this->_string_shift($response, 4)));
                    $value = $this->_string_shift($response, $length);
                    switch ($value) {
                        case 'exit-signal':
                            $this->_string_shift($response, 1);
                            extract(unpack('Nlength', $this->_string_shift($response, 4)));
                            $this->errors[] = 'SSH_MSG_CHANNEL_REQUEST (exit-signal): ' . $this->_string_shift($response, $length);
                            $this->_string_shift($response, 1);
                            extract(unpack('Nlength', $this->_string_shift($response, 4)));
                            if ($length) {
                                $this->errors[count($this->errors)].= "\r\n" . $this->_string_shift($response, $length);
                            }

                            $this->_send_binary_packet(pack('CN', Messages::NET_SSH2_MSG_CHANNEL_EOF, $this->server_channels[$client_channel]));
                            $this->_send_binary_packet(pack('CN', Messages::NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));

                            $this->channel_status[$channel] = Messages::NET_SSH2_MSG_CHANNEL_EOF;

                            break;
                        case 'exit-status':
                            extract(unpack('Cfalse/Nexit_status', $this->_string_shift($response, 5)));
                            $this->exit_status = $exit_status;
                            // "The channel needs to be closed with SSH_MSG_CHANNEL_CLOSE after this message."
                            // -- http://tools.ietf.org/html/rfc4254#section-6.10
                            $this->_send_binary_packet(pack('CN', Messages::NET_SSH2_MSG_CHANNEL_EOF, $this->server_channels[$client_channel]));
                            $this->_send_binary_packet(pack('CN', Messages::NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));

                            $this->channel_status[$channel] = Messages::NET_SSH2_MSG_CHANNEL_EOF;

                            break;
                        default:
                            // "Some systems may not implement signals, in which case they SHOULD ignore this message."
                            //  -- http://tools.ietf.org/html/rfc4254#section-6.9
                            break;
                    }
                    break;
                case Messages::NET_SSH2_MSG_CHANNEL_CLOSE:
                    $this->curTimeout = 0;

                    if ($this->bitmap & self::SSH2_MASK_SHELL) {
                        $this->bitmap&= ~self::SSH2_MASK_SHELL;
                    }
                    if ($this->channel_status[$channel] != Messages::NET_SSH2_MSG_CHANNEL_EOF) {
                        $this->_send_binary_packet(pack('CN', Messages::NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));
                    }

                    $this->channel_status[$channel] = Messages::NET_SSH2_MSG_CHANNEL_CLOSE;
                    return true;
                case Messages::NET_SSH2_MSG_CHANNEL_EOF:
                    break;
                default:
                    user_error('Error reading channel data');
                    return $this->_disconnect(DisconnectReasons::BY_APPLICATION);
            }
        }
    }

    /**
     * Sends Binary Packets
     *
     * See '6. Binary Packet Protocol' of rfc4253 for more info.
     *
     * @param String $data
     * @see SSH2::_get_binary_packet()
     * @return Boolean
     * @access private
     */
    function _send_binary_packet($data)
    {
        if (!is_resource($this->fsock) || feof($this->fsock)) {
            user_error('Connection closed prematurely');
            $this->bitmask = 0;
            return false;
        }

        //if ($this->compress) {
        //    // the -4 removes the checksum:
        //    // http://php.net/function.gzcompress#57710
        //    $data = substr(gzcompress($data), 0, -4);
        //}

        // 4 (packet length) + 1 (padding length) + 4 (minimal padding amount) == 9
        $packet_length = strlen($data) + 9;
        // round up to the nearest $this->encrypt_block_size
        $packet_length+= (($this->encrypt_block_size - 1) * $packet_length) % $this->encrypt_block_size;
        // subtracting strlen($data) is obvious - subtracting 5 is necessary because of packet_length and padding_length
        $padding_length = $packet_length - strlen($data) - 5;
        $padding = Random::crypt_random_string($padding_length);

        // we subtract 4 from packet_length because the packet_length field isn't supposed to include itself
        $packet = pack('NCa*', $packet_length - 4, $padding_length, $data . $padding);

        $hmac = $this->hmac_create !== false ? $this->hmac_create->hash(pack('Na*', $this->send_seq_no, $packet)) : '';
        $this->send_seq_no++;

        if ($this->encrypt !== false) {
            $packet = $this->encrypt->encrypt($packet);
        }

        $packet.= $hmac;

        $start = microtime(true); // http://php.net/microtime#61838
        $result = strlen($packet) == fputs($this->fsock, $packet);
        $stop = microtime(true);

        if (defined('SSH2_LOGGING')) {
            $current = microtime(true);
            $message_number = isset($this->message_numbers[ord($data[0])]) ? $this->message_numbers[ord($data[0])] : 'UNKNOWN (' . ord($data[0]) . ')';
            $message_number = '-> ' . $message_number .
                              ' (since last: ' . round($current - $this->last_packet, 4) . ', network: ' . round($stop - $start, 4) . 's)';
            $this->_append_log($message_number, $data);
            $this->last_packet = $current;
        }

        return $result;
    }

    /**
     * Logs data packets
     *
     * Makes sure that only the last 1MB worth of packets will be logged
     *
     * @param $message_number
     * @param $message
     * @internal param String $data
     */
    private function _append_log($message_number, $message)
    {
            switch (SSH2_LOGGING) {
                // useful for benchmarks
                case self::SSH2_LOG_SIMPLE:
                    $this->message_number_log[] = $message_number;
                    break;
                // the most useful log for SSH2
                case self::SSH2_LOG_COMPLEX:
                    $this->message_number_log[] = $message_number;
                    $this->_string_shift($message);
                    $this->log_size+= strlen($message);
                    $this->message_log[] = $message;
                    while ($this->log_size > self::SSH2_LOG_MAX_SIZE) {
                        $this->log_size-= strlen(array_shift($this->message_log));
                        array_shift($this->message_number_log);
                    }
                    break;
                // dump the output out realtime; packets may be interspersed with non packets,
                // passwords won't be filtered out and select other packets may not be correctly
                // identified
                case self::SSH2_LOG_REALTIME:
                    echo "<pre>\r\n" . $this->format_log(array($message), array($message_number)) . "\r\n</pre>\r\n";
                    @flush();
                    @ob_flush();
                    break;
                // basically the same thing as self::SSH2_LOG_REALTIME with the caveat that self::SSH2_LOG_REALTIME_FILE
                // needs to be defined and that the resultant log file will be capped out at self::SSH2_LOG_MAX_SIZE.
                // the earliest part of the log file is denoted by the first <<< START >>> and is not going to necessarily
                // at the beginning of the file
                case self::SSH2_LOG_REALTIME_FILE:
                    if (!isset($this->realtime_log_file)) {
                        // PHP doesn't seem to like using constants in fopen()
                        $filename = self::SSH2_LOG_REALTIME_FILENAME;
                        $fp = fopen($filename, 'w');
                        $this->realtime_log_file = $fp;
                    }
                    if (!is_resource($this->realtime_log_file)) {
                        break;
                    }
                    $entry = $this->format_log(array($message), array($message_number));
                    if ($this->realtime_log_wrap) {
                        $temp = "<<< START >>>\r\n";
                        $entry.= $temp;
                        fseek($this->realtime_log_file, ftell($this->realtime_log_file) - strlen($temp));
                    }
                    $this->realtime_log_size+= strlen($entry);
                    if ($this->realtime_log_size > self::SSH2_LOG_MAX_SIZE) {
                        fseek($this->realtime_log_file, 0);
                        $this->realtime_log_size = strlen($entry);
                        $this->realtime_log_wrap = true;
                    }
                    fputs($this->realtime_log_file, $entry);
            }
    }

    /**
     * Sends channel data
     *
     * Spans multiple SSH_MSG_CHANNEL_DATAs if appropriate
     *
     * @param Integer $client_channel
     * @param String $data
     * @return Boolean
     */
    private function _send_channel_packet($client_channel, $data)
    {
        $max_size = min(
            $this->packet_size_client_to_server[$client_channel],
            $this->window_size_client_to_server[$client_channel]
        );
        while (strlen($data) > $max_size) {
            $packet = pack('CN2a*',
                Messages::NET_SSH2_MSG_CHANNEL_DATA,
                $this->server_channels[$client_channel],
                $max_size,
                $this->_string_shift($data, $max_size)
            );

            $this->window_size_client_to_server[$client_channel]-= $max_size;

            if (!$this->_send_binary_packet($packet)) {
                return false;
            }

            if ($max_size == $this->window_size_client_to_server[$client_channel]) {
                $this->bitmap^= self::SSH2_MASK_WINDOW_ADJUST;
                // using an invalid channel will let the buffers be built up for the valid channels
                $this->_get_channel_packet(-1);
                $this->bitmap^= self::SSH2_MASK_WINDOW_ADJUST;
                $max_size = min(
                    $this->packet_size_client_to_server[$client_channel],
                    $this->window_size_client_to_server[$client_channel]
                );
            }
        }

        if (strlen($data) >= $this->window_size_client_to_server[$client_channel]) {
            $this->bitmap^= self::SSH2_MASK_WINDOW_ADJUST;
            $this->_get_channel_packet(-1);
            $this->bitmap^= self::SSH2_MASK_WINDOW_ADJUST;
        }

        $this->window_size_client_to_server[$client_channel]-= strlen($data);

        return $this->_send_binary_packet(pack('CN2a*',
            SSH2_MSG_CHANNEL_DATA,
            $this->server_channels[$client_channel],
            strlen($data),
            $data));
    }

    /**
     * Closes and flushes a channel
     *
     * SSH2 doesn't properly close most channels.  For exec() channels are normally closed by the server
     * and for SFTP channels are presumably closed when the client disconnects.  This functions is intended
     * for SCP more than anything.
     *
     * @param Integer $client_channel
     * @return Boolean
     */
    private function _close_channel($client_channel)
    {
        // see http://tools.ietf.org/html/rfc4254#section-5.3

        $this->_send_binary_packet(pack('CN', Messages::NET_SSH2_MSG_CHANNEL_EOF, $this->server_channels[$client_channel]));

        $this->_send_binary_packet(pack('CN', Messages::NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$client_channel]));

        $this->channel_status[$client_channel] = Messages::NET_SSH2_MSG_CHANNEL_CLOSE;

        $this->curTimeout = 0;

        while (!is_bool($this->_get_channel_packet($client_channel)));

        if ($this->bitmap & self::SSH2_MASK_SHELL) {
            $this->bitmap&= ~self::SSH2_MASK_SHELL;
        }
    }

    /**
     * Disconnect
     *
     * @param Integer $reason
     * @return Boolean
     * @access private
     */
    function _disconnect($reason)
    {
        if ($this->bitmap) {
            $data = pack('CNNa*Na*', Messages::NET_SSH2_MSG_DISCONNECT, $reason, 0, '', 0, '');
            $this->_send_binary_packet($data);
            $this->bitmap = 0;
            fclose($this->fsock);
            return false;
        }
    }

    /**
     * String Shift
     *
     * Inspired by array_shift
     *
     * @param String $string
     * @param optional Integer $index
     * @return String
     * @access private
     */
    function _string_shift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }

    /**
     * Returns a log of the packets that have been sent and received.
     *
     * Returns a string if SSH2_LOGGING == SSH2_LOG_COMPLEX, an array if SSH2_LOGGING == self::SSH2_LOG_SIMPLE and false if !defined('SSH2_LOGGING')
     *
     * @return String or Array
     */
    public function getLog()
    {
        if (!defined('SSH2_LOGGING')) {
            return false;
        }

        switch (SSH2_LOGGING) {
            case self::SSH2_LOG_SIMPLE:
                return $this->message_number_log;
                break;
            case self::SSH2_LOG_COMPLEX:
                return $this->format_log($this->message_log, $this->message_number_log);
                break;
            default:
                return false;
        }
    }

    /**
     * Formats a log for printing
     *
     * @param Array $message_log
     * @param Array $message_number_log
     * @return String
     */
    private function format_log($message_log, $message_number_log)
    {
        static $boundary = ':', $long_width = 65, $short_width = 16;

        $output = '';
        for ($i = 0; $i < count($message_log); $i++) {
            $output.= $message_number_log[$i] . "\r\n";
            $current_log = $message_log[$i];
            $j = 0;
            do {
                if (strlen($current_log)) {
                    $output.= str_pad(dechex($j), 7, '0', STR_PAD_LEFT) . '0  ';
                }
                $fragment = $this->_string_shift($current_log, $short_width);
                $hex = substr(
                           preg_replace(
                               '#(.)#es',
                               '"' . $boundary . '" . str_pad(dechex(ord(substr("\\1", -1))), 2, "0", STR_PAD_LEFT)',
                               $fragment),
                           strlen($boundary)
                       );
                // replace non ASCII printable characters with dots
                // http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters
                // also replace < with a . since < messes up the output on web browsers
                $raw = preg_replace('#[^\x20-\x7E]|<#', '.', $fragment);
                $output.= str_pad($hex, $long_width - $short_width, ' ') . $raw . "\r\n";
                $j++;
            } while (strlen($current_log));
            $output.= "\r\n";
        }

        return $output;
    }

    /**
     * Returns all errors
     *
     * @return String
     */
    public function getErrors()
    {
        return $this->errors;
    }

    /**
     * Returns the last error
     *
     * @return String
     */
    public function getLastError()
    {
        return $this->errors[count($this->errors) - 1];
    }

    /**
     * Return the server identification.
     *
     * @return String
     */
    public function getServerIdentification()
    {
        return $this->server_identifier;
    }

    /**
     * Return a list of the key exchange algorithms the server supports.
     *
     * @return Array
     */
    public function getKexAlgorithms()
    {
        return $this->kex_algorithms;
    }

    /**
     * Return a list of the host key (public key) algorithms the server supports.
     *
     * @return Array
     */
    public function getServerHostKeyAlgorithms()
    {
        return $this->server_host_key_algorithms;
    }

    /**
     * Return a list of the (symmetric key) encryption algorithms the server supports, when receiving stuff from the client.
     *
     * @return Array
     */
    public function getEncryptionAlgorithmsClient2Server()
    {
        return $this->encryption_algorithms_client_to_server;
    }

    /**
     * Return a list of the (symmetric key) encryption algorithms the server supports, when sending stuff to the client.
     *
     * @return Array
     */
    public function getEncryptionAlgorithmsServer2Client()
    {
        return $this->encryption_algorithms_server_to_client;
    }

    /**
     * Return a list of the MAC algorithms the server supports, when receiving stuff from the client.
     *
     * @return Array
     */
    public function getMACAlgorithmsClient2Server()
    {
        return $this->mac_algorithms_client_to_server;
    }

    /**
     * Return a list of the MAC algorithms the server supports, when sending stuff to the client.
     *
     * @return Array
     */
    public function getMACAlgorithmsServer2Client()
    {
        return $this->mac_algorithms_server_to_client;
    }

    /**
     * Return a list of the compression algorithms the server supports, when receiving stuff from the client.
     *
     * @return Array
     */
    public function getCompressionAlgorithmsClient2Server()
    {
        return $this->compression_algorithms_client_to_server;
    }

    /**
     * Return a list of the compression algorithms the server supports, when sending stuff to the client.
     *
     * @return Array
     */
    public function getCompressionAlgorithmsServer2Client()
    {
        return $this->compression_algorithms_server_to_client;
    }

    /**
     * Return a list of the languages the server supports, when sending stuff to the client.
     *
     * @return Array
     */
    public function getLanguagesServer2Client()
    {
        return $this->languages_server_to_client;
    }

    /**
     * Return a list of the languages the server supports, when receiving stuff from the client.
     *
     * @return Array
     */
    public function getLanguagesClient2Server()
    {
        return $this->languages_client_to_server;
    }

    /**
     * Returns the banner message.
     *
     * Quoting from the RFC, "in some jurisdictions, sending a warning message before
     * authentication may be relevant for getting legal protection."
     *
     * @return String
     */
    public function getBannerMessage()
    {
        return $this->banner_message;
    }

    /**
     * Returns the server public host key.
     *
     * Caching this the first time you connect to a server and checking the result on subsequent connections
     * is recommended.  Returns false if the server signature is not signed correctly with the public host key.
     *
     * @return mixed
     */
    public function getServerPublicHostKey()
    {
        $signature = $this->signature;
        $server_public_host_key = $this->server_public_host_key;

        extract(unpack('Nlength', $this->_string_shift($server_public_host_key, 4)));
        $this->_string_shift($server_public_host_key, $length);

        if ($this->signature_validated) {
            return $this->bitmap ?
                $this->signature_format . ' ' . base64_encode($this->server_public_host_key) :
                false;
        }

        $this->signature_validated = true;

        switch ($this->signature_format) {
            case 'ssh-dss':
                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $p = new BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $q = new BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $g = new BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $y = new BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                /* The value for 'dss_signature_blob' is encoded as a string containing
                   r, followed by s (which are 160-bit integers, without lengths or
                   padding, unsigned, and in network byte order). */
                $temp = unpack('Nlength', $this->_string_shift($signature, 4));
                if ($temp['length'] != 40) {
                    user_error('Invalid signature');
                    return $this->_disconnect(DisconnectReasons::KEY_EXCHANGE_FAILED);
                }

                $r = new BigInteger($this->_string_shift($signature, 20), 256);
                $s = new BigInteger($this->_string_shift($signature, 20), 256);

                if ($r->compare($q) >= 0 || $s->compare($q) >= 0) {
                    user_error('Invalid signature');
                    return $this->_disconnect(DisconnectReasons::KEY_EXCHANGE_FAILED);
                }

                $w = $s->modInverse($q);

                $u1 = $w->multiply(new BigInteger(sha1($this->exchange_hash), 16));
                list(, $u1) = $u1->divide($q);

                $u2 = $w->multiply($r);
                list(, $u2) = $u2->divide($q);

                $g = $g->modPow($u1, $p);
                $y = $y->modPow($u2, $p);

                $v = $g->multiply($y);
                list(, $v) = $v->divide($p);
                list(, $v) = $v->divide($q);

                if (!$v->equals($r)) {
                    user_error('Bad server signature');
                    return $this->_disconnect(DisconnectReasons::HOST_KEY_NOT_VERIFIABLE);
                }

                break;
            case 'ssh-rsa':
                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $e = new BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $n = new BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);
                $nLength = $temp['length'];

                /*
                $temp = unpack('Nlength', $this->_string_shift($signature, 4));
                $signature = $this->_string_shift($signature, $temp['length']);

                if (!class_exists('RSA')) {
                    require_once('Crypt/RSA.php');
                }

                $rsa = new RSA();
                $rsa->setSignatureMode(RSA_SIGNATURE_PKCS1);
                $rsa->loadKey(array('e' => $e, 'n' => $n), RSA_PUBLIC_FORMAT_RAW);
                if (!$rsa->verify($this->exchange_hash, $signature)) {
                    user_error('Bad server signature');
                    return $this->_disconnect(SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }
                */

                $temp = unpack('Nlength', $this->_string_shift($signature, 4));
                $s = new BigInteger($this->_string_shift($signature, $temp['length']), 256);

                // validate an RSA signature per "8.2 RSASSA-PKCS1-v1_5", "5.2.2 RSAVP1", and "9.1 EMSA-PSS" in the
                // following URL:
                // ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf

                // also, see SSHRSA.c (rsa2_verifysig) in PuTTy's source.

                if ($s->compare(new BigInteger()) < 0 || $s->compare($n->subtract(new BigInteger(1))) > 0) {
                    user_error('Invalid signature');
                    return $this->_disconnect(DisconnectReasons::KEY_EXCHANGE_FAILED);
                }

                $s = $s->modPow($e, $n);
                $s = $s->toBytes();

                $h = pack('N4H*', 0x00302130, 0x0906052B, 0x0E03021A, 0x05000414, sha1($this->exchange_hash));
                $h = chr(0x01) . str_repeat(chr(0xFF), $nLength - 3 - strlen($h)) . $h;

                if ($s != $h) {
                    user_error('Bad server signature');
                    return $this->_disconnect(DisconnectReasons::HOST_KEY_NOT_VERIFIABLE);
                }
                break;
            default:
                user_error('Unsupported signature format');
                return $this->_disconnect(DisconnectReasons::HOST_KEY_NOT_VERIFIABLE);
        }

        return $this->signature_format . ' ' . base64_encode($this->server_public_host_key);
    }

    /**
     * Returns the exit status of an SSH command or false.
     *
     * @return Integer|false
     */
    public function getExitStatus()
    {
        if (is_null($this->exit_status)) {
            return false;
        }
        return $this->exit_status;
    }

    public function getPacketSizeClientToServer()
    {
        return $this->packet_size_client_to_server;
    }
}
