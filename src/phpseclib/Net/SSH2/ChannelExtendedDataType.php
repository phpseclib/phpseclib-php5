<?php


namespace PhpSecLib\Net\SSH2;

/**
 * SSH_MSG_CHANNEL_EXTENDED_DATA's data_type_codes
 *
 * @link http://tools.ietf.org/html/rfc4254#section-5.2
 * @see SSH2::SSH2()
 * @var Array
 * @access private
 */
class ChannelExtendedDataType {
    const NET_SSH2_EXTENDED_DATA_STDERR = 1;
} 