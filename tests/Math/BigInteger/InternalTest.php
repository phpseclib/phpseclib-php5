<?php
use PhpSecLib\Math\BigInteger;

/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Math_BigInteger_InternalTest extends Math_BigInteger_TestCase
{
	static public function setUpBeforeClass()
	{
		parent::setUpBeforeClass();

		self::ensureConstant('MATH_BIGINTEGER_MODE', BigInteger::MATH_BIGINTEGER_MODE_INTERNAL);
		self::ensureConstant('MATH_BIGINTEGER_OPENSSL_DISABLE', true);
	}
}
