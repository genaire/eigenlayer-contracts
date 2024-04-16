// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "./StrategyBase.sol";
import "../permissions/Pausable.sol";

/**
 * @title TODO: write this
 * @author Layr Labs, Inc.
 * @notice TODO: write this
 */
contract StrategyFactory is OwnableUpgradeable, Pausable {

    uint8 internal constant PAUSED_NEW_STRATEGIES = 0;

    /// @notice EigenLayer's StrategyManager contract
    IStrategyManager public immutable strategyManager;

    StrategyBase public immutable strategyImplementation;

    ProxyAdmin public eigenLayerProxyAdmin;

    // @notice Mapping token => strategy contract for the token
    mapping(IERC20 => IStrategy) public tokenStrategies;

    event ProxyAdminChanged(ProxyAdmin previousProxyAdmin, ProxyAdmin newProxyAdmin);
    event StrategySetForToken(IERC20 token, IStrategy strategy);

    /// @notice Since this contract is designed to be initializable, the constructor simply sets the immutable variables.
    constructor(IStrategyManager _strategyManager, StrategyBase _strategyImplementation) {
        strategyManager = _strategyManager;
        strategyImplementation = _strategyImplementation;
        _disableInitializers();
    }

    function initialize(
        address _initialOwner,
        IPauserRegistry _pauserRegistry,
        uint256 _initialPausedStatus,
        ProxyAdmin _eigenLayerProxyAdmin
    )
        public virtual initializer
    {
        _transferOwnership(_initialOwner);
        _initializePauser(_pauserRegistry, _initialPausedStatus);
        // TODO: decide if a function for changing this is warranted
        eigenLayerProxyAdmin = _eigenLayerProxyAdmin;
        emit ProxyAdminChanged(ProxyAdmin(address(0)), _eigenLayerProxyAdmin);
    }

    // TODO: document with ample warnings
    function deployNewStrategy(IERC20 token) external onlyWhenNotPaused(PAUSED_NEW_STRATEGIES) {
        require(tokenStrategies[token] == IStrategy(address(0)),
            "StrategyFactory.deployNewStrategy: Strategy already exists for token");
        IStrategy strategy = IStrategy(
            address(
                new TransparentUpgradeableProxy(
                    address(strategyImplementation),
                    address(eigenLayerProxyAdmin),
                    abi.encodeWithSelector(StrategyBase.initialize.selector, token, pauserRegistry)
                )
            )
        );
        _setStrategyForToken(token, strategy);
    }

    /** 
     * @notice Owner-only function to pass through a call to `StrategyManager.addStrategiesToDepositWhitelist`
     * @dev Also adds the `strategiesToWhitelist` to the `tokenStrategies` mapping
     */
    function whitelistStrategies(
        IStrategy[] calldata strategiesToWhitelist,
        bool[] calldata thirdPartyTransfersForbiddenValues
    ) external onlyOwner {
        strategyManager.addStrategiesToDepositWhitelist(strategiesToWhitelist, thirdPartyTransfersForbiddenValues);
        for (uint256 i = 0; i < strategiesToWhitelist.length; ++i) {
            IERC20 underlyingToken = strategiesToWhitelist[i].underlyingToken();
            _setStrategyForToken(underlyingToken, strategiesToWhitelist[i]);
        }
    }

    // @notice Owner-only function to add (existing) Strategy contracts to the `tokenStrategies` mapping
    function editTokenStrategiesMapping(
        IERC20[] calldata tokens,
        IStrategy[] calldata strategies
    ) external onlyOwner {
        require(tokens.length == strategies.length,
            "StrategyFactory.editTokenStrategiesMapping: input length mismatch");
        for (uint256 i = 0; i < tokens.length; ++i) {
            _setStrategyForToken(tokens[i], strategies[i]);
        }
    }

    function _setStrategyForToken(IERC20 token, IStrategy strategy) internal {
        tokenStrategies[token] = strategy;
        emit StrategySetForToken(token, strategy);
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}
