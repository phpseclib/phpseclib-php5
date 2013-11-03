<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace PhpSecLib\Net;

/**
 * Pure-PHP implementation of SCP.
 *
 * PHP versions 4 and 5
 *
 * The API for this library is modeled after the API from PHP's {@link http://php.net/book.ftp FTP extension}.
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    $ssh = new SSH2('www.domain.tld');
 *    if (!$ssh->login('username', 'password')) {
 *        exit('bad login');
 *    }

 *    $scp = new SCP($ssh);
 *    $scp->put('abcd', str_repeat('x', 1024*1024));
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
 * @package    SCP
 * @author     Jim Wigginton <terrafrost@php.net>
 * @copyright  MMX Jim Wigginton
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       http://phpseclib.sourceforge.net
 */

/**
 * Pure-PHP implementations of SCP.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 *
 * @TODO: maybe use extend clause instead of access some private methods from SSH
 */
class SCP {
    /**
     * @see SCP::put()
     * Reads data from a local file.
     */
    const NET_SCP_LOCAL_FILE = 1;
    /**
     * @see SCP::put()
     * Reads data from a string.
     */
    const NET_SCP_STRING = 2;


    /**
     * @see SCP::_send()
     * @see SCP::_receive()
     * SSH1 is being used.
     */
    const NET_SCP_SSH1 = 1;

    /**
     * @see SCP::send()
     * @see SCP::receive()
     * SSH2 is being used.
     */
    const NET_SCP_SSH2 = 2;

    /**
     * SSH Object
     *
     * @var Object
     */
    private $ssh;

    /**
     * Packet Size
     *
     * @var Integer
     */
    private $packet_size;

    /**
     * Mode
     *
     * @var Integer
     */
    private $mode;

    /**
     * Default Constructor.
     *
     * Connects to an SSH server
     *
     * @param $ssh
     * @return SCP
     *
     * @throws \InvalidArgumentException
     */
    public function __construct($ssh)
    {
        if (!is_object($ssh)) {
            return;
        }

        if($ssh instanceof SSH2) {
            $this->mode = self::NET_SCP_SSH2;
        } elseif($ssh instanceof SSH1) {
                $this->packet_size = 50000;
                $this->mode = self::NET_SCP_SSH1;
        } else {
            throw new \InvalidArgumentException('You have to provide a SSH connection');
        }


        $this->ssh = $ssh;
    }

    /**
     * Uploads a file to the SCP server.
     *
     * By default, SCP::put() does not read from the local filesystem.  $data is dumped directly into $remote_file.
     * So, for example, if you set $data to 'filename.ext' and then do SCP::get(), you will get a file, twelve bytes
     * long, containing 'filename.ext' as its contents.
     *
     * Setting $mode to NET_SFTP_LOCAL_FILE will change the above behavior.  With NET_SFTP_LOCAL_FILE, $remote_file will 
     * contain as many bytes as filename.ext does on your local filesystem.  If your filename.ext is 1MB then that is how
     * large $remote_file will be, as well.
     *
     * Currently, only binary mode is supported.  As such, if the line endings need to be adjusted, you will need to take
     * care of that, yourself.
     *
     * @param String $remote_file
     * @param String $data
     * @param optional Integer $mode
     * @return Boolean
     * @access public
     */
    public function put($remote_file, $data, $mode = self::NET_SCP_STRING)
    {
        if (!isset($this->ssh)) {
            return false;
        }

        $this->ssh->exec('scp -t ' . $remote_file, false); // -t = to

        $temp = $this->receive();
        if ($temp !== chr(0)) {
            return false;
        }

        if ($this->mode == self::NET_SCP_SSH2) {
            $this->packet_size = $this->ssh->getPacketSizeClientToServer()[SSH2::SSH2_CHANNEL_EXEC];
        }

        $remote_file = basename($remote_file);
        $this->send('C0644 ' . strlen($data) . ' ' . $remote_file . "\n");

        $temp = $this->receive();
        if ($temp !== chr(0)) {
            return false;
        }

        if ($mode == self::NET_SCP_STRING) {
            $this->send($data);
        } else {
            if (!is_file($data)) {
                user_error("$data is not a valid file", E_USER_NOTICE);
                return false;
            }
            $fp = @fopen($data, 'rb');
            if (!$fp) {
                return false;
            }
            $size = filesize($data);
            for ($i = 0; $i < $size; $i += $this->packet_size) {
                $this->send(fgets($fp, $this->packet_size));
            }
            fclose($fp);	
        }
        $this->close();
    }

    /**
     * Downloads a file from the SCP server.
     *
     * Returns a string containing the contents of $remote_file if $local_file is left undefined or a boolean false if
     * the operation was unsuccessful.  If $local_file is defined, returns true or false depending on the success of the
     * operation
     *
     * @param String $remote_file
     * @param bool $local_file
     * @return Mixed
     */
    public function get($remote_file, $local_file = false)
    {
        if (!isset($this->ssh)) {
            return false;
        }

        $this->ssh->exec('scp -f ' . $remote_file, false); // -f = from

        $this->send("\0");

        if (!preg_match('#(?<perms>[^ ]+) (?<size>\d+) (?<name>.+)#', rtrim($this->receive()), $info)) {
            return false;
        }

        $this->send("\0");

        $size = 0;

        if ($local_file !== false) {
            $fp = @fopen($local_file, 'wb');
            if (!$fp) {
                return false;
            }
        }

        $content = '';
        while ($size < $info['size']) {
            $data = $this->receive();
            // SCP usually seems to split stuff out into 16k chunks
            $size+= strlen($data);

            if ($local_file === false) {
                $content.= $data;
            } else {
                fputs($fp, $data);
            }
        }

        $this->close();

        if ($local_file !== false) {
            fclose($fp);
            return true;
        }

        return $content;
    }

    /**
     * Sends a packet to an SSH server
     *
     * @param String $data
     */
    private function send($data)
    {
        switch ($this->mode) {
            case self::NET_SCP_SSH2:
                $this->ssh->_send_channel_packet(SSH2::NET_SSH2_CHANNEL_EXEC, $data);
                break;
            case self::NET_SCP_SSH1:
                $data = pack('CNa*', SSH1::NET_SSH1_CMSG_STDIN_DATA, strlen($data), $data);
                $this->ssh->_send_binary_packet($data);
         }
    }

    /**
     * Receives a packet from an SSH server
     *
     * @return String
     */
    private function receive()
    {
        switch ($this->mode) {
            case self::NET_SCP_SSH2:
                return $this->ssh->_get_channel_packet(SSH2::NET_SSH2_CHANNEL_EXEC, true);
            case self::NET_SCP_SSH1:
                if (!$this->ssh->bitmap) {
                    return false;
                }
                while (true) {
                    $response = $this->ssh->_get_binary_packet();
                    switch ($response[NET_SSH1_RESPONSE_TYPE]) {
                        case SSH1::NET_SSH1_SMSG_STDOUT_DATA:
                            extract(unpack('Nlength', $response[NET_SSH1_RESPONSE_DATA]));
                            return $this->ssh->_string_shift($response[NET_SSH1_RESPONSE_DATA], $length);
                        case SSH1::NET_SSH1_SMSG_STDERR_DATA:
                            break;
                        case SSH1::NET_SSH1_SMSG_EXITSTATUS:
                            $this->ssh->_send_binary_packet(chr(SSH1::NET_SSH1_CMSG_EXIT_CONFIRMATION));
                            fclose($this->ssh->fsock);
                            $this->ssh->bitmap = 0;
                            return false;
                        default:
                            user_error('Unknown packet received', E_USER_NOTICE);
                            return false;
                    }
                }
         }
    }

    /**
     * Closes the connection to an SSH server
     */
    private function close()
    {
        switch ($this->mode) {
            case self::NET_SCP_SSH2:
                $this->ssh->_close_channel(self::NET_SSH2_CHANNEL_EXEC);
                break;
            case self::NET_SCP_SSH1:
                $this->ssh->disconnect();
         }
    }
}
