pragma solidity ^0.6.7;

import "geb-proxy-actions/GebProxyActions.sol";

import "./uni/v3/interfaces/IUniswapV3Pool.sol";
import "./uni/v3/interfaces/IUniswapV3Factory.sol";

abstract contract OracleRelayerLike {
    function redemptionPrice() public virtual returns (uint);
    function collateralTypes(bytes32) public virtual view returns (address, uint, uint);
}

abstract contract OracleLike {
    function read() public virtual view returns (uint);
}

// Proxy to perform both swaps and flashswaps
// Necessary because Uni pool will callback on swaps, callbacks direcly to DSProxy will revert.
// In order to use it a proxy call needs to define this contract as it's authority before calling it and revoke the access immediately after callback (flashswaps only).
contract UniswapV3Proxy is DSAuthority {
    uint160 internal constant MIN_SQRT_RATIO = 4295128739;
    uint160 internal constant MAX_SQRT_RATIO = 1461446703485210103287273052203988822378723970342;
    IUniswapV3Factory internal constant factory = IUniswapV3Factory(0x0);
    address proxy;
    IUniswapV3Pool pool;
    address proxyActions = msg.sender;

    event log(string);
    event log(address);

    /// @notice Called to `msg.sender` after executing a swap via IUniswapV3Pool#swap.
    /// @dev In the implementation you must pay the pool tokens owed for the swap.
    /// The caller of this method must be checked to be a UniswapV3Pool deployed by the canonical UniswapV3Factory.
    /// amount0Delta and amount1Delta can both be 0 if no tokens were swapped.
    /// @param _amount0 The amount of token0 that was sent (negative) or must be received (positive) by the pool by
    /// the end of the swap. If positive, the callback must send that amount of token0 to the pool.
    /// @param _amount1 The amount of token1 that was sent (negative) or must be received (positive) by the pool by
    /// the end of the swap. If positive, the callback must send that amount of token1 to the pool.
    /// @param _data Any data passed through by the caller via the IUniswapV3PoolActions#swap call
    function uniswapV3SwapCallback(int256 _amount0, int256 _amount1, bytes calldata _data) external {
        require(msg.sender == address(pool), "invalid callback");

        // transfer coins
        if (_amount0 < int(0))
            DSTokenLike(pool.token0()).transfer(proxy, uint256(_amount0 * -1));
        else
            DSTokenLike(pool.token1()).transfer(proxy, uint256(_amount1 * -1));

        (address sender, bytes memory outerData) = abi.decode(_data, (address, bytes));
        require(sender == proxy, "invalid callback");

        // call proxy (proxy needs to repay swap on callback)
        (bool success,) = proxy.call(
            abi.encodeWithSignature("execute(address,bytes)",
                proxyActions,
                abi.encodeWithSignature("swapCallback(address,int256,int256,bytes)", msg.sender, _amount0, _amount1, outerData)
            )
        );
        require(success, "call failed");
        pool = IUniswapV3Pool(0);
        proxy = address(0);
    }

    /// @notice Initiates a (flash)swap
    /// @param _pool Pool in wich to perform the swap
    /// @param zeroForOne Direction of the swap
    /// @param amount Amount to borrow
    /// @param data Callback data, it will call this contract with the raw data
    function swap(IUniswapV3Pool _pool, bool zeroForOne, uint amount, uint160 sqrtLimitPrice, bytes calldata data) external {
        if (sqrtLimitPrice == 0)
            sqrtLimitPrice = zeroForOne ? MIN_SQRT_RATIO + 1 : MAX_SQRT_RATIO - 1;

        bytes memory innerData = abi.encode(msg.sender, data);

        pool = _pool;
        proxy = msg.sender;
        pool.swap(address(this), zeroForOne, int256(amount) * -1, sqrtLimitPrice, innerData);
    }

    function canCall(
        address src, address dst, bytes4 sig
    ) external override view returns (bool) {
        if( src == address(this) &&
            dst == proxy &&
            sig == 0x1cff79cd)
            return true;
    }

    fallback() external payable {}

}

contract GebHyperLeveragerActions is BasicActions {
    UniswapV3Proxy immutable uniV3Proxy = new UniswapV3Proxy();

    /// @notice Opens Safe, locks Eth, and leverages it to a user defined ratio
    /// @param uniV3Pool address
    /// @param uniV3AuxPool address
    /// @param manager address
    /// @param ethJoin address
    /// @param taxCollector address
    /// @param coinJoin address
    /// @param oracleRelayer address
    /// @param collateralType bytes32 - The ETH type used to generate debt
    /// @param leverage uint - leverage ratio, 3 decimal places, 2.5 == 2500
    function openLockETHLeverage(
        address uniV3Pool,
        address uniV3AuxPool,
        address manager,
        address ethJoin,
        address taxCollector,
        address coinJoin,
        address oracleRelayer,
        bytes32 collateralType,
        uint256 leverage
    ) public payable returns (uint safe) {
        safe = openSAFE(manager, collateralType, address(this));
        _lockETH(manager, ethJoin, safe, msg.value);
        flashLeverage(
            uniV3Pool,
            uniV3AuxPool,
            manager,
            ethJoin,
            taxCollector,
            coinJoin,
            oracleRelayer,
            collateralType,
            safe,
            leverage
        );
    }

    /// @notice Locks Eth, and leverages it to a user defined ratio
    /// @param uniV3Pool address
    /// @param uniV3AuxPool address
    /// @param manager address
    /// @param ethJoin address
    /// @param taxCollector address
    /// @param coinJoin address
    /// @param oracleRelayer address
    /// @param collateralType bytes32
    /// @param safe uint - Safe Id
    /// @param leverage uint - leverage ratio, 3 decimal places, 2.5 == 2500
    function lockETHLeverage(
        address uniV3Pool,
        address uniV3AuxPool,
        address manager,
        address ethJoin,
        address taxCollector,
        address coinJoin,
        address oracleRelayer,
        bytes32 collateralType,
        uint safe,
        uint leverage // 3 decimal places, 2.5 == 2500
    ) public payable {
        _lockETH(manager, ethJoin, safe, msg.value);
        flashLeverage(
            uniV3Pool,
            uniV3AuxPool,
            manager,
            ethJoin,
            taxCollector,
            coinJoin,
            oracleRelayer,
            collateralType,
            safe,
            leverage
        );
    }

    /// @notice Leverages a safe to a user defined ratio
    /// @param uniV3Pool address
    /// @param uniV3AuxPool address
    /// @param manager address
    /// @param ethJoin address
    /// @param taxCollector address
    /// @param coinJoin address
    /// @param oracleRelayer address
    /// @param safe uint256 - Safe Id
    /// @param leverage uint256 - leverage ratio, 3 decimal places, 2.5 == 2500
    function flashLeverage(
        address uniV3Pool,
        address uniV3AuxPool,
        address manager,
        address ethJoin,
        address taxCollector,
        address coinJoin,
        address oracleRelayer,
        bytes32 collateralType,
        uint256 safe,
        uint256 leverage // 3 decimal places, 2.5 == 2500
    ) public {
        bytes memory data;
        { // stack too deep
            data = abi.encode(
                manager,
                ethJoin,
                safe,
                taxCollector,
                coinJoin,
                uniV3Pool,
                uniV3AuxPool
            );
        }

        DSAuth(address(this)).setAuthority(DSAuthority(address(uniV3Proxy)));
        // increasing leverage
        uniV3Proxy.swap(
            IUniswapV3Pool(uniV3Pool),
            address(CollateralJoinLike(ethJoin).collateral()) == IUniswapV3Pool(uniV3Pool).token1(),
            getTokenAmount(manager, oracleRelayer, collateralType, safe, leverage),
            0,
            data
        );
    }

    function getTokenAmount(address manager, address oracleRelayer, bytes32 collateralType, uint safe, uint desiredLeverage) internal returns (uint) {
            (uint collateralBalance, uint debtBalance) = SAFEEngineLike(ManagerLike(manager).safeEngine()).safes(collateralType, ManagerLike(manager).safes(safe));

            (address collateralOracle,, uint liquidationCRatio) = OracleRelayerLike(oracleRelayer).collateralTypes(collateralType);

            // check real leverage
            uint net = collateralBalance - ((debtBalance * OracleRelayerLike(oracleRelayer).redemptionPrice()) / (1e9 * OracleLike(collateralOracle).read()));

            return subtract((multiply(net, desiredLeverage) / 1000), net);
    }

    function swapCallback(IUniswapV3Pool _pool, int256 _amount0, int256 _amount1, bytes calldata _data) external {
        uint amountToRepay = _amount0 > int(0) ? uint(_amount0) : uint(_amount1);
        CollateralLike tokenToRepay = _amount0 > int(0) ? CollateralLike(_pool.token0()) : CollateralLike(_pool.token1());

        // decode data
        (,,,,,address uniV3Pool,) = abi.decode(_data, (address, address, uint, address, address, address, IUniswapV3Pool));

        if (address(_pool) == uniV3Pool) { // flashSwap

            (address manager, address ethJoin, uint safe,,,, IUniswapV3Pool uniV3AuxPool) = abi.decode(_data, (address, address, uint, address, address, address, IUniswapV3Pool));

            uint collateralAmount = _amount0 < int(0) ? uint(-_amount0) : uint(-_amount1);
            WethLike(address(CollateralJoinLike(ethJoin).collateral())).withdraw(collateralAmount);
            _lockETH(manager, ethJoin, safe, collateralAmount);

            // swap secondary secondary weth for exact amount of secondary token
            uniV3Proxy.swap(uniV3AuxPool, address(tokenToRepay) == uniV3AuxPool.token1(), amountToRepay, 0, _data);
        } else {
            (address manager,, uint safe, address taxCollector, address coinJoin,,) = abi.decode(_data, (address, address, uint, address, address, address, IUniswapV3Pool));

            _generateDebt(manager, taxCollector, coinJoin, safe, amountToRepay, address(this));
            DSAuth(address(this)).setAuthority(DSAuthority(address(0)));
        }

        tokenToRepay.transfer(address(_pool), amountToRepay);
    }
}
