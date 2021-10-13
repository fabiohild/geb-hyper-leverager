pragma solidity ^0.6.7;

import "ds-test/test.sol";

import "./GebHyperLeverager.sol";

contract GebHyperLeveragerTest is DSTest {
    GebHyperLeverager leverager;

    function setUp() public {
        leverager = new GebHyperLeverager();
    }

    function testFail_basic_sanity() public {
        assertTrue(false);
    }

    function test_basic_sanity() public {
        assertTrue(true);
    }
}
