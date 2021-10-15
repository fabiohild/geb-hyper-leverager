// Copyright (C) 2021 Reflexer Labs, INC

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

pragma solidity 0.6.7;

import "geb-safe-saviours/interfaces/SafeSaviourLike.sol";
import "geb-safe-saviours/math/SafeMath.sol";
import "ds-token/token.sol";
import "./uni/v3/interfaces/IUniswapV3Pool.sol";

contract NativeUnderlyingUniswapV2SafeSaviour is SafeMath, SafeSaviourLike {
    // --- Auth ---
    mapping (address => uint256) public authorizedAccounts;
    /**
     * @notice Add auth to an account
     * @param account Account to add auth to
     */
    function addAuthorization(address account) external isAuthorized {
        authorizedAccounts[account] = 1;
        emit AddAuthorization(account);
    }
    /**
     * @notice Remove auth from an account
     * @param account Account to remove auth from
     */
    function removeAuthorization(address account) external isAuthorized {
        authorizedAccounts[account] = 0;
        emit RemoveAuthorization(account);
    }
    /**
    * @notice Checks whether msg.sender can call an authed function
    **/
    modifier isAuthorized {
        require(authorizedAccounts[msg.sender] == 1, "NativeUnderlyingUniswapV2SafeSaviour/account-not-authorized");
        _;
    }

    // --- Variables ---
    // The ERC20 system coin
    ERC20Like                      public systemCoin;
    // The system coin join contract
    CoinJoinLike                   public coinJoin;
    // The collateral join contract for adding collateral in the system
    CollateralJoinLike             public collateralJoin;
    // The collateral token
    ERC20Like                      public collateralToken;
    // Oracle providing the system coin price feed
    PriceFeedLike                  public systemCoinOrcl;
    // Coin pair (i.e: RAI/XYZ)
    IUniswapV3Pool                 public uniswapPair;
    // Pair used to swap non system coin token to ETH, (i.e: XYZ/ETH)
    IUniswapV3Pool                 public auxiliaryUniPair;

    // Percentage of collateral used to unwind position
    mapping(address => uint256)    public cover;

    uint256 public   constant ZERO           = 0;
    uint160 internal constant MIN_SQRT_RATIO = 4295128739;
    uint160 internal constant MAX_SQRT_RATIO = 1461446703485210103287273052203988822378723970342;

    // --- Events ---
    event AddAuthorization(address account);
    event RemoveAuthorization(address account);
    event ModifyParameters(bytes32 indexed parameter, uint256 val);
    event ModifyParameters(bytes32 indexed parameter, address data);
    event Set(
      address indexed caller,
      address indexed safeHandler,
      uint256 ratio
    );

    constructor(
        address coinJoin_,
        address collateralJoin_,
        address systemCoinOrcl_,
        address liquidationEngine_,
        address taxCollector_,
        address oracleRelayer_,
        address safeManager_,
        address saviourRegistry_,
        address liquidityManager_,
        uint256 minKeeperPayoutValue_
    ) public {
        require(coinJoin_ != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-coin-join");
        require(collateralJoin_ != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-collateral-join");
        require(systemCoinOrcl_ != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-system-coin-oracle");
        require(oracleRelayer_ != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-oracle-relayer");
        require(liquidationEngine_ != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-liquidation-engine");
        require(taxCollector_ != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-tax-collector");
        require(safeManager_ != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-safe-manager");
        require(saviourRegistry_ != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-saviour-registry");
        require(minKeeperPayoutValue_ > 0, "NativeUnderlyingUniswapV2SafeSaviour/invalid-min-payout-value");

        authorizedAccounts[msg.sender] = 1;

        minKeeperPayoutValue = minKeeperPayoutValue_;

        coinJoin             = CoinJoinLike(coinJoin_);
        collateralJoin       = CollateralJoinLike(collateralJoin_);
        liquidationEngine    = LiquidationEngineLike(liquidationEngine_);
        taxCollector         = TaxCollectorLike(taxCollector_);
        oracleRelayer        = OracleRelayerLike(oracleRelayer_);
        systemCoinOrcl       = PriceFeedLike(systemCoinOrcl_);
        systemCoin           = ERC20Like(coinJoin.systemCoin());
        safeEngine           = SAFEEngineLike(coinJoin.safeEngine());
        safeManager          = GebSafeManagerLike(safeManager_);
        saviourRegistry      = SAFESaviourRegistryLike(saviourRegistry_);
        collateralToken      = ERC20Like(collateralJoin.collateral());

        systemCoinOrcl.getResultWithValidity();
        oracleRelayer.redemptionPrice();

        require(collateralJoin.contractEnabled() == 1, "NativeUnderlyingUniswapV2SafeSaviour/join-disabled");
        require(address(collateralToken) != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-col-token");
        require(address(safeEngine) != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-safe-engine");
        require(address(systemCoin) != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-sys-coin");

        emit AddAuthorization(msg.sender);
        emit ModifyParameters("minKeeperPayoutValue", minKeeperPayoutValue);
        emit ModifyParameters("oracleRelayer", oracleRelayer_);
        emit ModifyParameters("taxCollector", taxCollector_);
        emit ModifyParameters("systemCoinOrcl", systemCoinOrcl_);
        emit ModifyParameters("liquidationEngine", liquidationEngine_);
    }

    // --- Administration ---
    /**
     * @notice Modify an uint256 param
     * @param parameter The name of the parameter
     * @param val New value for the parameter
     */
    function modifyParameters(bytes32 parameter, uint256 val) external isAuthorized {
        if (parameter == "minKeeperPayoutValue") {
            require(val > 0, "NativeUnderlyingUniswapV2SafeSaviour/null-min-payout");
            minKeeperPayoutValue = val;
        }
        else revert("NativeUnderlyingUniswapV2SafeSaviour/modify-unrecognized-param");
        emit ModifyParameters(parameter, val);
    }
    /**
     * @notice Modify an address param
     * @param parameter The name of the parameter
     * @param data New address for the parameter
     */
    function modifyParameters(bytes32 parameter, address data) external isAuthorized {
        require(data != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-data");

        if (parameter == "systemCoinOrcl") {
            systemCoinOrcl = PriceFeedLike(data);
            systemCoinOrcl.getResultWithValidity();
        }
        else if (parameter == "oracleRelayer") {
            oracleRelayer = OracleRelayerLike(data);
            oracleRelayer.redemptionPrice();
        }
        else if (parameter == "liquidationEngine") {
            liquidationEngine = LiquidationEngineLike(data);
        }
        else if (parameter == "taxCollector") {
            taxCollector = TaxCollectorLike(data);
        }
        else revert("NativeUnderlyingUniswapV2SafeSaviour/modify-unrecognized-param");
        emit ModifyParameters(parameter, data);
    }

    // --- Internal Utils ---
    /// @notice Initiates a (flash)swap
    /// @param pool Pool in wich to perform the swap
    /// @param zeroForOne Direction of the swap
    /// @param amount Amount to borrow
    /// @param data Callback data, it will call this contract with the raw data
    function _startSwap(IUniswapV3Pool pool, bool zeroForOne, uint amount, uint160 sqrtLimitPrice, bytes memory data) internal {
        if (sqrtLimitPrice == 0)
            sqrtLimitPrice = zeroForOne ? MIN_SQRT_RATIO + 1 : MAX_SQRT_RATIO - 1;

        pool.swap(address(this), zeroForOne, int256(amount) * -1, sqrtLimitPrice, data);
    }

    // --- Setup Cover ---
    /*
    * @notice Set up a percentage of collateral to be used to unwind position upon liquidation
    * @param safeID The ID of the SAFE to protect. This ID should be registered inside GebSafeManager
    * @param coverPercentage Percentage of collateral used to unwind position. (WAD)
    */
    function setup(uint256 safeID, uint256 coverPercentage) external controlsSAFE(msg.sender, safeID) {
        require(coverPercentage > 0, "NativeUnderlyingUniswapV2SafeSaviour/invalid-percentage");

        // Check that the SAFE exists inside GebSafeManager
        address safeHandler = safeManager.safes(safeID);
        require(safeHandler != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-handler");

        // Check that the SAFE has debt
        (, uint256 safeDebt) =
          SAFEEngineLike(collateralJoin.safeEngine()).safes(collateralJoin.collateralType(), safeHandler);
        require(safeDebt > 0, "NativeUnderlyingUniswapV2SafeSaviour/safe-does-not-have-debt");

        cover[safeHandler] = coverPercentage;

        emit Set(msg.sender, safeHandler, coverPercentage);
    }

    // --- Uni Callback Logic ---
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
        require(msg.sender == address(uniswapPair) || msg.sender == address(auxiliaryUniPair), "GebUniswapV3MultiHopKeeperFlashProxy/invalid-uniswap-pair");

        uint amountToRepay = _amount0 > int(0) ? uint(_amount0) : uint(_amount1);
        IUniswapV3Pool pool = IUniswapV3Pool(msg.sender);
        DSToken tokenToRepay = _amount0 > int(ZERO) ? DSToken(pool.token0()) : DSToken(pool.token1());

        if (msg.sender == address(uniswapPair)) { // flashswap
            // join COIN
            uint amount = systemCoin.balanceOf(address(this));
            systemCoin.approve(address(coinJoin), amount);
            coinJoin.join(address(this), amount);

            (uint safeDebtRepaid, uint keeperPayoutTokens, uint exitCollateral, address safeHandler, bytes32 collateralType) = abi.decode(_data, (uint, uint, uint, address, bytes32));

            // repay collateral
            // Approve the coin join contract to take system coins and repay debt

            systemCoin.approve(address(coinJoin), safeDebtRepaid);
            // Calculate the non adjusted system coin amount
            uint256 nonAdjustedSystemCoinsToRepay = div(mul(safeDebtRepaid, RAY), getAccumulatedRate(collateralType));

            // Join system coins in the system and repay the SAFE's debt
            coinJoin.join(address(this), safeDebtRepaid);
            safeEngine.modifySAFECollateralization(
                collateralType,
                safeHandler,
                address(0),
                address(this),
                int256(0),
                -int256(safeDebtRepaid - keeperPayoutTokens)
            );

            // exit WETH
            // collateralJoin.exit(safeHandler, exitCollateral);

            // swap secondary secondary weth for exact amount of secondary token
            _startSwap(auxiliaryUniPair, address(tokenToRepay) == auxiliaryUniPair.token1(), amountToRepay, 0, "");
        }
        // pay for swap
        tokenToRepay.transfer(msg.sender, amountToRepay);
    }

    // --- Saving Logic ---
    /*
    * @notice Saves a SAFE by withdrawing liquidity and repaying debt and/or adding more collateral
    * @dev Only the LiquidationEngine can call this
    * @param keeper The keeper that called LiquidationEngine.liquidateSAFE and that should be rewarded for spending gas to save a SAFE
    * @param collateralType The collateral type backing the SAFE that's being liquidated
    * @param safeHandler The handler of the SAFE that's being liquidated
    * @return Whether the SAFE has been saved, the amount of LP tokens that were used to withdraw liquidity as well as the amount of
    *         system coins sent to the keeper as their payment (this implementation always returns 0)
    */
    function saveSAFE(address keeper, bytes32 collateralType, address safeHandler) override external returns (bool, uint256, uint256) {
        require(address(liquidationEngine) == msg.sender, "NativeUnderlyingUniswapV2SafeSaviour/caller-not-liquidation-engine");
        require(keeper != address(0), "NativeUnderlyingUniswapV2SafeSaviour/null-keeper-address");

        if (both(both(collateralType == "", safeHandler == address(0)), keeper == address(liquidationEngine))) {
            return (true, uint(-1), uint(-1));
        }

        // Check that this is handling the correct collateral
        require(collateralType == collateralJoin.collateralType(), "NativeUnderlyingUniswapV2SafeSaviour/invalid-collateral-type");

        // Check that the SAFE has a non null amount of LP tokens covering it
        require(cover[safeHandler] > 0, "NativeUnderlyingUniswapV2SafeSaviour/null-cover");

        // Tax the collateral
        taxCollector.taxSingle(collateralType);

        // // Get the amounts of tokens sent to the keeper as payment
        (uint256 depositedCollateralToken, uint256 safeDebt) =
          SAFEEngineLike(collateralJoin.safeEngine()).safes(collateralJoin.collateralType(), safeHandler);

        // Fetch the amount of tokens used to save the SAFE
        uint safeCollateralUsed = cover[safeHandler] * depositedCollateralToken / 100 ether;
        uint safeDebtRepaid = (safeCollateralUsed / getCollateralPrice()) * getSystemCoinMarketPrice();

        // Fetch the amount of tokens sent to the keeper
        uint256 keeperSysCoins = getKeeperPayoutTokens(safeHandler, oracleRelayer.redemptionPrice(), safeDebtRepaid);

        // // There must be tokens that go to the keeper
        require(both(keeperSysCoins > 0, safeDebtRepaid> 0), "NativeUnderlyingUniswapV2SafeSaviour/cannot-pay-keeper");

        // Mark the SAFE in the registry as just having been saved
        saviourRegistry.markSave(collateralType, safeHandler);

        // Save the SAFE
        // loan RAI/repay debt
        bytes memory data = abi.encode(safeDebtRepaid, keeperSysCoins, safeCollateralUsed, safeHandler, collateralType);
        _startSwap(uniswapPair, address(systemCoin) == uniswapPair.token1() ,safeDebtRepaid, 0, data);

        // Emit an event
        emit SaveSAFE(keeper, collateralType, safeHandler, cover[safeHandler]);

        return (true, cover[safeHandler], 0);
    }

    // --- Getters ---
    /*
    * @notify Must be implemented according to the interface although it always returns 0
    */
    function getKeeperPayoutValue() override public returns (uint256) {
        return 0;
    }
    /*
    * @notify Must be implemented according to the interface although it always returns false
    */
    function keeperPayoutExceedsMinValue() override public returns (bool) {
        return false;
    }
    /*
    * @notice Determine whether a SAFE can be saved with the current amount of lpTokenCover deposited as cover for it
    * @param safeHandler The handler of the SAFE which the function takes into account
    * @return Whether the SAFE can be saved or not
    */
    function canSave(bytes32, address safeHandler) override external returns (bool) {
        // Fetch the redemption price first
        uint256 redemptionPrice = oracleRelayer.redemptionPrice();

        (uint256 depositedCollateralToken, uint256 safeDebt) =
          SAFEEngineLike(collateralJoin.safeEngine()).safes(collateralJoin.collateralType(), safeHandler);

        // Fetch the amount of tokens used to save the SAFE
        uint safeCollateralUsed = cover[safeHandler] * depositedCollateralToken / 100 ether;
        uint safeDebtRepaid = (safeCollateralUsed / getCollateralPrice()) * getSystemCoinMarketPrice();

        // Fetch the amount of tokens sent to the keeper
        uint256 keeperSysCoins = getKeeperPayoutTokens(safeHandler, redemptionPrice, safeDebtRepaid);

        return keeperSysCoins > 0;
    }

    /*
    * @notify Fetch the collateral's price
    */
    function getCollateralPrice() public view returns (uint256) {
        (address ethFSM,,) = oracleRelayer.collateralTypes(collateralJoin.collateralType());
        if (ethFSM == address(0)) return 0;

        (uint256 priceFeedValue, bool hasValidValue) = PriceFeedLike(ethFSM).getResultWithValidity();
        if (!hasValidValue) return 0;

        return priceFeedValue;
    }
    /*
    * @notify Fetch the system coin's market price
    */
    function getSystemCoinMarketPrice() public view returns (uint256) {
        (uint256 priceFeedValue, bool hasValidValue) = systemCoinOrcl.getResultWithValidity();
        if (!hasValidValue) return 0;

        return priceFeedValue;
    }

    // /*
    // * @notice Return the amount of system coins and/or collateral tokens used to pay a keeper
    // * @param safeHandler The handler/address of the targeted SAFE
    // * @param redemptionPrice The system coin redemption price used in calculations
    // * @param safeDebtRepaid The amount of system coins that are already used to save the targeted SAFE
    // */
    function getKeeperPayoutTokens(address safeHandler, uint256 redemptionPrice, uint256 safeDebtRepaid)
      public view returns (uint256) {
        // Get the system coin and collateral market prices
        uint256 collateralPrice    = getCollateralPrice();
        uint256 sysCoinMarketPrice = getSystemCoinMarketPrice();
        if (either(collateralPrice == 0, sysCoinMarketPrice == 0)) {
            return 0;
        }

        // Check if the keeper can get system coins and if yes, compute how many
        uint256 keeperSysCoins;
        uint256 payoutInSystemCoins  = div(mul(minKeeperPayoutValue, WAD), sysCoinMarketPrice);

        if (safeDebtRepaid <= payoutInSystemCoins) {
            return payoutInSystemCoins;
        } else {
            return 0;
        }
    }
    /*
    * @notice Return the total amount of collateral used to repay debt
    * @param collateralType The SAFE collateral type (ignored in this implementation)
    * @param safeHandler The handler of the SAFE which the function takes into account
    * @return The collateral percentage used for cover
    */
    function tokenAmountUsedToSave(bytes32, address safeHandler) override public returns (uint256) {
        return cover[safeHandler];
    }
    /*
    * @notify Returns whether a target debt amount is below the debt floor of a specific collateral type
    * @param collateralType The collateral type whose floor we compare against
    * @param targetDebtAmount The target debt amount for a SAFE that has collateralType collateral in it
    */
    function debtBelowFloor(bytes32 collateralType, uint256 targetDebtAmount) public view returns (bool) {
        (, , , , uint256 debtFloor, ) = safeEngine.collateralTypes(collateralType);
        return (mul(targetDebtAmount, RAY) < debtFloor);
    }
    /*
    * @notify Get the accumulated interest rate for a specific collateral type
    * @param The collateral type for which to retrieve the rate
    */
    function getAccumulatedRate(bytes32 collateralType)
      public view returns (uint256 accumulatedRate) {
        (, accumulatedRate, , , , ) = safeEngine.collateralTypes(collateralType);
    }
}
