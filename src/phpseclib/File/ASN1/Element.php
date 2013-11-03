<?php


namespace PhpSecLib\File\ASN1;


/**
 * ASN.1 Element
 *
 * Bypass normal encoding rules in ASN1::encodeDER()
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class Element {
    /**
     * Raw element value
     *
     * @var String
     */
    private $element;

    public function __construct($encoded)
    {
        $this->element = $encoded;
    }
}