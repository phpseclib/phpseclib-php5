<?php
use PhpSecLib\Crypt\Hash;

/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

abstract class Crypt_Hash_TestCase extends PhpseclibTestCase
{
	static public function setUpBeforeClass()
	{
		if (!defined('Hash_MODE'))
		{
			define('Hash_MODE', Hash::CRYPT_HASH_MODE_INTERNAL);
		}
	}

	public function setUp()
	{
		if (defined('Hash_MODE') && Hash_MODE !== Hash::CRYPT_HASH_MODE_INTERNAL)
		{
			$this->markTestSkipped('Skipping test because Hash_MODE is not defined as Hash::Hash_MODE_INTERNAL.');
		}
	}

	protected function assertHashesTo(Hash $hash, $message, $expected)
	{
		$this->assertEquals(
			strtolower($expected),
			bin2hex($hash->hash($message)),
			sprintf("Failed asserting that '%s' hashes to '%s'.", $message, $expected)
		);
	}

	protected function assertHMACsTo(Hash $hash, $key, $message, $expected)
	{
		$hash->setKey($key);

		$this->assertEquals(
			strtolower($expected),
			bin2hex($hash->hash($message)),
			sprintf("Failed asserting that '%s' HMACs to '%s' with key '%s'.", $message, $expected, $key)
		);
	}
}
