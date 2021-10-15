pragma solidity 0.6.7;

import "ds-test/test.sol";
import "ds-weth/weth9.sol";
import "ds-token/token.sol";

import {GebProxyActions, GebHyperLeveragerActions} from "../GebHyperLeverager.sol";

import {Feed, GebDeployTestBase, EnglishCollateralAuctionHouse} from "geb-deploy/test/GebDeploy.t.base.sol";
import {DGD, GNT} from "./tokens.sol";
import {CollateralJoin3, CollateralJoin4} from "geb-deploy/AdvancedTokenAdapters.sol";
import {DSValue} from "ds-value/value.sol";
import {GebSafeManager} from "geb-safe-manager/GebSafeManager.sol";
import {GetSafes} from "geb-safe-manager/GetSafes.sol";
import {GebProxyRegistry, DSProxyFactory, DSProxy} from "geb-proxy-registry/GebProxyRegistry.sol";
import {GebProxyIncentivesActions} from "geb-proxy-actions/GebProxyIncentivesActions.sol";

import "../uni/v3/UniswapV3Factory.sol";
import "../uni/v3/UniswapV3Pool.sol";
import {LiquidityAmounts} from "../uni/v3/libraries/LiquidityAmounts.sol";

contract ProxyCalls {
    DSProxy proxy;
    address gebProxyLeverageActions;

    function transfer(address, address, uint256) public {
        proxy.execute(gebProxyLeverageActions, msg.data);
    }

    function openSAFE(address, bytes32, address) public returns (uint safe) {
        bytes memory response = proxy.execute(gebProxyLeverageActions, msg.data);
        assembly {
            safe := mload(add(response, 0x20))
        }
    }

    function lockETH(address, address, uint) public payable {
        (bool success,) = address(proxy).call{value: msg.value}(abi.encodeWithSignature("execute(address,bytes)", gebProxyLeverageActions, msg.data));
        require(success, "");
    }

    function generateDebt(address, address, address, uint, uint) public {
        proxy.execute(gebProxyLeverageActions, msg.data);
    }

    function openLockETHLeverage(address, address, address, address, address, address, address, bytes32, uint) public payable returns (uint safe) {
        address payable target = address(proxy);
        bytes memory data = abi.encodeWithSignature("execute(address,bytes)", gebProxyLeverageActions, msg.data);
        assembly {
            let succeeded := call(sub(gas(), 5000), target, callvalue(), add(data, 0x20), mload(data), 0, 0)
            let size := returndatasize()
            let response := mload(0x40)
            mstore(0x40, add(response, and(add(add(size, 0x20), 0x1f), not(0x1f))))
            mstore(response, size)
            returndatacopy(add(response, 0x20), 0, size)

            safe := mload(add(response, 0x60))

            switch iszero(succeeded)
            case 1 {
                // throw if delegatecall failed
                revert(add(response, 0x20), size)
            }
        }
    }

    function lockETHLeverage(address, address, address, address, address, address, address, bytes32, uint, uint) public payable {
        (bool success,) = address(proxy).call{value: msg.value}(abi.encodeWithSignature("execute(address,bytes)", gebProxyLeverageActions, msg.data));
        require(success, "");
    }

    function flashLeverage(address, address, address, address, address, address, address, bytes32, uint, uint) public {
        (bool success,) = address(proxy).call(abi.encodeWithSignature("execute(address,bytes)", gebProxyLeverageActions, msg.data));
        require(success, "");
    }
}

contract GebProxyLeverageActionsTest is GebDeployTestBase, ProxyCalls {
    GebSafeManager manager;

    GebProxyRegistry registry;
    DSToken rewardToken;

    DSToken ext;

    UniswapV3Pool raiEXTPair;
    UniswapV3Pool extETHPair;

    bytes32 collateralAuctionType = bytes32("FIXED-DISCOUNT");

    function setUp() override public {
        super.setUp();
        deployStableKeepAuth(collateralAuctionType);
        this.modifyParameters(address(safeEngine), "ETH", "debtCeiling", uint(0) - 1);
        this.modifyParameters(address(safeEngine), "globalDebtCeiling", uint(0) - 1);

        manager = new GebSafeManager(address(safeEngine));
        DSProxyFactory factory = new DSProxyFactory();
        registry = new GebProxyRegistry(address(factory));
        gebProxyLeverageActions = address(new GebHyperLeveragerActions());
        proxy = DSProxy(registry.build());

        ext = new DSToken("EXT", "EXT");
        ext.mint(100000000 ether);

        // Setup Uniswap
        raiEXTPair = UniswapV3Pool(_deployV3Pool(address(coin), address(ext), 500));
        raiEXTPair.initialize(address(coin) == raiEXTPair.token0() ? 45742400955009932534161870629 : 137227202865029797602485611888);

        extETHPair = UniswapV3Pool(_deployV3Pool(address(ext), address(weth), 3000));
        extETHPair.initialize(address(ext) == extETHPair.token0() ? 43395051798747794894315217866 : 1446501726624926496477173928);

        // Add pair liquidity
        uint safe = this.openSAFE(address(manager), "ETH", address(proxy));
        this.lockETH{value: 500000 ether}(address(manager), address(ethJoin), safe);
        this.generateDebt(address(manager), address(taxCollector), address(coinJoin), safe, 100000000 ether);

        weth.deposit{value: 1000000 ether}();
        _addWhaleLiquidity();

        // zeroing balances
        coin.transfer(address(1), coin.balanceOf(address(this)));
        weth.transfer(address(1), weth.balanceOf(address(this)));
        ext.transfer(address(1), ext.balanceOf(address(this)));
    }

    // --- Helpers ---
    function _deployV3Pool(
        address _token0,
        address _token1,
        uint256 _fee
    ) internal returns (address _pool) {
        UniswapV3Factory fac = new UniswapV3Factory();
        _pool = fac.createPool(_token0, _token1, uint24(_fee));
    }

    function _addWhaleLiquidity() internal {
        int24 low = -887220;
        int24 upp = 887220;

        // coin/ext
        (uint160 sqrtRatioX96, , , , , , ) = raiEXTPair.slot0();
        uint128 liq;
        if (address(coin) == raiEXTPair.token0())
            liq = _getLiquidityAmountsForTicks(sqrtRatioX96, low, upp, 10000 ether, 30000 ether);
        else
            liq = _getLiquidityAmountsForTicks(sqrtRatioX96, low, upp, 30000 ether,  10000 ether);
        raiEXTPair.mint(address(this), low, upp, liq, bytes(""));

        // ext/eth
        (sqrtRatioX96, , , , , , ) = extETHPair.slot0();
        if (address(ext) == extETHPair.token0())
            liq = _getLiquidityAmountsForTicks(sqrtRatioX96, low, upp, 300000 ether, 10000 ether);
        else
            liq = _getLiquidityAmountsForTicks(sqrtRatioX96, low, upp, 10000  ether,  300000 ether);
        extETHPair.mint(address(this), low, upp, liq, bytes(""));
    }

    function uniswapV3MintCallback(
        uint256 amount0Owed,
        uint256 amount1Owed,
        bytes calldata
    ) external {
        DSToken(UniswapV3Pool(msg.sender).token0()).transfer(msg.sender, amount0Owed);
        DSToken(UniswapV3Pool(msg.sender).token1()).transfer(msg.sender, amount1Owed);
    }

    function _getLiquidityAmountsForTicks(
        uint160 sqrtRatioX96,
        int24 _lowerTick,
        int24 upperTick,
        uint256 t0am,
        uint256 t1am
    ) public pure returns (uint128 liquidity) {
        liquidity = LiquidityAmounts.getLiquidityForAmounts(
            sqrtRatioX96,
            TickMath.getSqrtRatioAtTick(_lowerTick),
            TickMath.getSqrtRatioAtTick(upperTick),
            t0am,
            t1am
        );
    }

    function lockedCollateral(bytes32 collateralType, address urn) public view returns (uint lktCollateral) {
        (lktCollateral,) = safeEngine.safes(collateralType, urn);
    }

    function generatedDebt(bytes32 collateralType, address urn) public view returns (uint genDebt) {
        (,genDebt) = safeEngine.safes(collateralType, urn);
    }

    // proxy should retain no balances, except for liquidity mining ownership
    modifier assertProxyEndsWithNoBalance() {
        _;
        assertEq(address(proxy).balance, 0);
        assertEq(coin.balanceOf(address(proxy)), 0);
    }

    // --- Tests ---

    function testOpenLockETHLeverage() public assertProxyEndsWithNoBalance {
        uint256 safe = this.openLockETHLeverage{value: 1 ether}(address(extETHPair), address(raiEXTPair), address(manager), address(ethJoin), address(taxCollector), address(coinJoin), address(oracleRelayer), "ETH", 2200); // 2.2x leverage
        assertEq(lockedCollateral("ETH", manager.safes(safe)), 2.2 ether);
        assertEq(generatedDebt("ETH", manager.safes(safe)), 12058089607693728517);
    }

    function testLockETHLeverage() public assertProxyEndsWithNoBalance {
        uint256 safe = this.openSAFE(address(manager), "ETH", address(proxy));

        this.lockETHLeverage{value: 1 ether}(address(extETHPair), address(raiEXTPair), address(manager), address(ethJoin), address(taxCollector), address(coinJoin), address(oracleRelayer), "ETH", safe, 2200); // 2.2x leverage
        assertEq(lockedCollateral("ETH", manager.safes(safe)), 2.2 ether);
        assertEq(generatedDebt("ETH", manager.safes(safe)), 12058089607693728517);
    }

    function testFlashLeverage() public assertProxyEndsWithNoBalance {
        uint256 safe = this.openSAFE(address(manager), "ETH", address(proxy));
        this.lockETH{value: 1 ether}(address(manager), address(ethJoin), safe);
        assertEq(lockedCollateral("ETH", manager.safes(safe)), 1 ether);

        this.flashLeverage(address(extETHPair), address(raiEXTPair), address(manager), address(ethJoin), address(taxCollector), address(coinJoin), address(oracleRelayer), "ETH", safe, 1100); // 1.1x leverage
        assertEq(lockedCollateral("ETH", manager.safes(safe)), 1.1 ether);

        this.flashLeverage(address(extETHPair), address(raiEXTPair), address(manager), address(ethJoin), address(taxCollector), address(coinJoin), address(oracleRelayer), "ETH", safe, 1100); // 1.1x leverage
        assertEq(lockedCollateral("ETH", manager.safes(safe)), 1209665459505723995);

        this.flashLeverage(address(extETHPair), address(raiEXTPair), address(manager), address(ethJoin), address(taxCollector), address(coinJoin), address(oracleRelayer), "ETH", safe, 2000); // 2.0x leverage
        assertEq(lockedCollateral("ETH", manager.safes(safe)), 2412315911723022812);
    }
}