<?php


namespace PhpSecLib\File\ASN1;


/**
 * ASN.1 Element
 *
 * Bypass normal encoding rules in ASN1::encodeDER()
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @version 0.3.0
 * @access  public
 * @package ASN1
 */
class Element {
    /**
     * Raw element value
     *
     * @var String
     * @access private
     */
    var $element;

    /**
     * Constructor
     *
     * @param String $encoded
     * @return Element
     * @access public
     */
    function File_ASN1_Element($encoded)
    {
        $this->element = $encoded;
    }
}