// SPDX-License-Identifier: BUSL-1.1
pragma solidity =0.8.12;

// Imports
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";
import "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "forge-std/Test.sol";

import "src/contracts/core/DelegationManager.sol";
import "src/contracts/core/StrategyManager.sol";
import "src/contracts/core/Slasher.sol";
import "src/contracts/strategies/StrategyBase.sol";
import "src/contracts/pods/EigenPodManager.sol";
import "src/contracts/pods/EigenPod.sol";
import "src/contracts/pods/DelayedWithdrawalRouter.sol";
import "src/contracts/permissions/PauserRegistry.sol";

import "src/test/mocks/EmptyContract.sol";
import "src/test/mocks/ETHDepositMock.sol";
import "src/test/mocks/BeaconChainOracleMock.sol";

import "src/test/integration/users/User.sol";

abstract contract IntegrationDeployer is Test {

    Vm cheats = Vm(HEVM_ADDRESS);

    // Core contracts to deploy
    DelegationManager delegationManager;
    StrategyManager strategyManager;
    EigenPodManager eigenPodManager;
    PauserRegistry pauserRegistry;
    Slasher slasher;
    IBeacon eigenPodBeacon;
    EigenPod pod;
    DelayedWithdrawalRouter delayedWithdrawalRouter;

    // Base strategy implementation in case we want to create more strategies later
    StrategyBase baseStrategyImplementation;

    // List of LST strategies
    IStrategy[] _strategies;

    // TODO - rename to time machine??
    Global global;

    // Lists of strategies used in the system
    //
    // When we select random user assets, we use the `assetType` to determine
    // which of these lists to select user assets from.
    IStrategy[] lstStrats;
    IStrategy[] ethStrats;   // only has one strat tbh
    IStrategy[] mixedStrats; // just a combination of the above 2 lists

    // Mock Contracts to deploy
    ETHPOSDepositMock ethPOSDeposit;
    BeaconChainOracleMock beaconChainOracle;

    // ProxyAdmin
    ProxyAdmin eigenLayerProxyAdmin;
    // Admin Addresses
    address eigenLayerReputedMultisig = address(this); // admin address
    address constant pauser = address(555);
    address constant unpauser = address(556);
    
    // Randomness state vars

    bytes32 random;

    // After calling `_configRand`, these are the allowed "variants" on users that will
    // be returned from `_randUser`.
    bytes assetTypes;
    bytes signedTypes;


    // Constants
    uint64 constant MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR = 32e9;
    uint64 constant GOERLI_GENESIS_TIME = 1616508000;
    IStrategy constant BEACONCHAIN_ETH_STRAT = IStrategy(0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0);
    uint constant MIN_BALANCE = 1e6;
    uint constant MAX_BALANCE = 5e6;

    // Flags

    uint constant FLAG = 1;

    /// @dev Asset flags
    /// These are used with _configRand to determine what assets are given
    /// to a user when they are created.
    uint constant NO_ASSETS = (FLAG << 0); // will have no assets
    uint constant HOLDS_LST = (FLAG << 1); // will hold some random amount of LSTs
    uint constant HOLDS_ETH = (FLAG << 2); // will hold some random amount of ETH
    uint constant HOLDS_MIX = (FLAG << 3); // will hold a mix of LSTs and ETH

    /// @dev Signing flags
    /// These are used with _configRand to determine whether a user will use "WithSignature"-type methods
    uint constant NO_SIGNED_METHODS = (FLAG << 0);
    uint constant SIGNED_METHODS = (FLAG << 1);

    // /// @dev Withdrawal flags
    // /// These are used with _configRand to determine how a user conducts a withdrawal
    // uint constant FULL_WITHDRAW_SINGLE = (FLAG << 0); // stakers will withdraw all assets using a single queued withdrawal
    // uint constant FULL_WITHDRAW_MULTI  = (FLAG << 1); // stakers will withdraw all assets using multiple queued withdrawals
    // uint constant PART_WITHDRAW_SINGLE = (FLAG << 2); // stakers will withdraw some, but not all assets

    /// Note: Thought about the following flags (but did not implement) -
    ///
    /// WithdrawerType (SELF_WITHDRAWER, OTHER_WITHDRAWER)
    ///     - especially with EPM share handling, this felt like it deserved its own test rather than a fuzzy state
    /// CompletionType (AS_TOKENS, AS_SHARES)
    ///     - same reason as above
    ///
    /// DepositMethod (DEPOSIT_STD, DEPOSIT_WITH_SIG)
    ///     - could still do this!
    /// WithdrawalMethod (QUEUE_WITHDRAWAL, UNDELEGATE, REDELEGATE)
    ///     - could still do this! 
    ///     - This would trigger staker.queueWithdrawals to use either `queueWithdrawals` or `undelegate` under the hood
    ///     - "redelegate" would be like the above, but adding a new `delegateTo` step after undelegating

    mapping(uint => string) assetTypeToStr;
    mapping(uint => string) signedTypeToStr;

    constructor () {
        assetTypeToStr[NO_ASSETS] = "NO_ASSETS";
        assetTypeToStr[HOLDS_LST] = "HOLDS_LST";
        assetTypeToStr[HOLDS_ETH] = "HOLDS_ETH";
        assetTypeToStr[HOLDS_MIX] = "HOLDS_MIX";
        
        signedTypeToStr[NO_SIGNED_METHODS] = "NO_SIGNED_METHODS";
        signedTypeToStr[SIGNED_METHODS] = "SIGNED_METHODS";
    }

    function setUp() public virtual {
        // Deploy ProxyAdmin
        eigenLayerProxyAdmin = new ProxyAdmin();

        // Deploy PauserRegistry
        address[] memory pausers = new address[](1);
        pausers[0] = pauser;
        pauserRegistry = new PauserRegistry(pausers, unpauser);

        // Deploy mocks
        EmptyContract emptyContract = new EmptyContract();
        ethPOSDeposit = new ETHPOSDepositMock();
        beaconChainOracle = new BeaconChainOracleMock();

        /**
         * First, deploy upgradeable proxy contracts that **will point** to the implementations. Since the implementation contracts are
         * not yet deployed, we give these proxies an empty contract as the initial implementation, to act as if they have no code.
         */
        delegationManager = DelegationManager(
            address(new TransparentUpgradeableProxy(address(emptyContract), address(eigenLayerProxyAdmin), ""))
        );
        strategyManager = StrategyManager(
            address(new TransparentUpgradeableProxy(address(emptyContract), address(eigenLayerProxyAdmin), ""))
        );
        slasher = Slasher(
            address(new TransparentUpgradeableProxy(address(emptyContract), address(eigenLayerProxyAdmin), ""))
        );
        eigenPodManager = EigenPodManager(
            address(new TransparentUpgradeableProxy(address(emptyContract), address(eigenLayerProxyAdmin), ""))
        );
        delayedWithdrawalRouter = DelayedWithdrawalRouter(
            address(new TransparentUpgradeableProxy(address(emptyContract), address(eigenLayerProxyAdmin), ""))
        );

        // Deploy EigenPod Contracts
        pod = new EigenPod(
            ethPOSDeposit,
            delayedWithdrawalRouter,
            eigenPodManager,
            MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR,
            GOERLI_GENESIS_TIME
        );

        eigenPodBeacon = new UpgradeableBeacon(address(pod));

        // Second, deploy the *implementation* contracts, using the *proxy contracts* as inputs
        DelegationManager delegationImplementation = new DelegationManager(strategyManager, slasher, eigenPodManager);
        StrategyManager strategyManagerImplementation = new StrategyManager(delegationManager, eigenPodManager, slasher);
        Slasher slasherImplementation = new Slasher(strategyManager, delegationManager);
        EigenPodManager eigenPodManagerImplementation = new EigenPodManager(
            ethPOSDeposit,
            eigenPodBeacon,
            strategyManager,
            slasher,
            delegationManager
        );
        DelayedWithdrawalRouter delayedWithdrawalRouterImplementation = new DelayedWithdrawalRouter(eigenPodManager);

        // Third, upgrade the proxy contracts to point to the implementations
        // DelegationManager
        eigenLayerProxyAdmin.upgradeAndCall(
            TransparentUpgradeableProxy(payable(address(delegationManager))),
            address(delegationImplementation),
            abi.encodeWithSelector(
                DelegationManager.initialize.selector,
                eigenLayerReputedMultisig, // initialOwner
                pauserRegistry,
                0 // initialPausedStatus
            )
        );
        // StrategyManager
        eigenLayerProxyAdmin.upgradeAndCall(
            TransparentUpgradeableProxy(payable(address(strategyManager))),
            address(strategyManagerImplementation),
            abi.encodeWithSelector(
                StrategyManager.initialize.selector,
                eigenLayerReputedMultisig, //initialOwner
                eigenLayerReputedMultisig, //initial whitelister
                pauserRegistry,
                0 // initialPausedStatus
            )
        );
        // Slasher
        eigenLayerProxyAdmin.upgradeAndCall(
            TransparentUpgradeableProxy(payable(address(slasher))),
            address(slasherImplementation),
            abi.encodeWithSelector(
                Slasher.initialize.selector,
                eigenLayerReputedMultisig,
                pauserRegistry,
                0 // initialPausedStatus
            )
        );
        // EigenPodManager
        eigenLayerProxyAdmin.upgradeAndCall(
            TransparentUpgradeableProxy(payable(address(eigenPodManager))),
            address(eigenPodManagerImplementation),
            abi.encodeWithSelector(
                EigenPodManager.initialize.selector,
                type(uint256).max, // maxPods
                address(beaconChainOracle),
                eigenLayerReputedMultisig, // initialOwner
                pauserRegistry,
                0 // initialPausedStatus
            )
        );
        // Delayed Withdrawal Router
        uint256 withdrawalDelayBlocks = 7 days / 12 seconds;
        eigenLayerProxyAdmin.upgradeAndCall(
            TransparentUpgradeableProxy(payable(address(delayedWithdrawalRouter))),
            address(delayedWithdrawalRouterImplementation),
            abi.encodeWithSelector(
                DelayedWithdrawalRouter.initialize.selector,
                eigenLayerReputedMultisig, // initialOwner
                pauserRegistry,
                0, // initialPausedStatus
                withdrawalDelayBlocks
            )
        );

        // Create base strategy implementation and deploy a few strategies
        baseStrategyImplementation = new StrategyBase(strategyManager);

        _newStrategyAndToken("Strategy1Token", "str1", 10e50, address(this)); // initialSupply, owner
        _newStrategyAndToken("Strategy2Token", "str2", 10e50, address(this)); // initialSupply, owner
        _newStrategyAndToken("Strategy3Token", "str3", 10e50, address(this)); // initialSupply, owner

        ethStrats.push(BEACONCHAIN_ETH_STRAT);
        mixedStrats.push(BEACONCHAIN_ETH_STRAT);

        global = new Global();
    }

    /// @dev Deploy a strategy and its underlying token, push to global lists of tokens/strategies, and whitelist
    /// strategy in strategyManager
    function _newStrategyAndToken(string memory tokenName, string memory tokenSymbol, uint initialSupply, address owner) internal {
        IERC20 underlyingToken = new ERC20PresetFixedSupply(tokenName, tokenSymbol, initialSupply, owner); 
        StrategyBase strategy = StrategyBase(
            address(
                new TransparentUpgradeableProxy(
                    address(baseStrategyImplementation),
                    address(eigenLayerProxyAdmin),
                    abi.encodeWithSelector(StrategyBase.initialize.selector, underlyingToken, pauserRegistry)
                )
            )
        );

        // Push to list of tokens/strategies
        _strategies.push(strategy);

        // Whitelist strategy
        IStrategy[] memory strategies = new IStrategy[](1);
        strategies[0] = strategy;
        strategyManager.addStrategiesToDepositWhitelist(strategies);

        // Add to lstStrats and mixedStrats
        lstStrats.push(strategy);
        mixedStrats.push(strategy);
    } 

    function _configRand(
        uint16 _randomSeed, 
        uint _assetTypes,
        uint _signedTypes
    ) internal {
        // Using uint16 for the seed type so that if a test fails, it's easier
        // to manually use the seed to replay the same test.
        // TODO - should we expand the type?
        emit log_named_uint("_configRand: set random seed to: ", _randomSeed);
        random = keccak256(abi.encodePacked(_randomSeed));

        emit log_named_uint("_configRand: allowed asset types: ", _assetTypes);

        // Convert flag bitmaps to bytes of set bits for easy use with _randUint
        assetTypes = _bitmapToBytes(_assetTypes);
        signedTypes = _bitmapToBytes(_signedTypes);

        emit log("_configRand: users will be initialized with these asset types:");
        for (uint i = 0; i < assetTypes.length; i++) {
            emit log(assetTypeToStr[uint(uint8(assetTypes[i]))]);
        }

        emit log("_configRand: users will be initialized with these signed types:");
        for (uint i = 0; i < signedTypes.length; i++) {
            emit log(signedTypeToStr[uint(uint8(signedTypes[i]))]);
        }

        assertTrue(assetTypes.length != 0, "_configRand: no asset types selected");
        assertTrue(signedTypes.length != 0, "_configRand: no signed types selected");
    }

    /**
     * @dev Create a new User with a random config using the range defined in `_configRand`
     * 
     * Assets are pulled from `strategies` based on a random staker/operator `assetType`
     */
    function _randUser() internal returns (User, IStrategy[] memory, uint[] memory) {
        // For the new user, select what type of assets they'll have and whether
        // they'll use `xWithSignature` methods.
        //
        // The values selected here are in the ranges configured via `_configRand`
        uint assetType = _randAssetType();
        uint signedType = _randSignedType();
        
        // Create User contract based on deposit type:
        User user;
        if (signedType == NO_SIGNED_METHODS) {
            user = new User(delegationManager, strategyManager, eigenPodManager, global);
        } else if (signedType == SIGNED_METHODS) {
            // User will use `delegateToBySignature` and `depositIntoStrategyWithSignature`
            user = User(new User_SignedMethods(delegationManager, strategyManager, eigenPodManager, global));
        } else {
            revert("_newUser: unimplemented signedType");
        }

        // For the specific asset selection we made, get a random assortment of
        // strategies and deal the user some corresponding underlying token balances
        (IStrategy[] memory strategies, uint[] memory tokenBalances) = _dealRandAssets(user, assetType);

        _printUserInfo(assetType, signedType, strategies, tokenBalances);

        return (user, strategies, tokenBalances);
    }

    /// @dev For a given `assetType`, select a random assortment of strategies and assets
    /// NO_ASSETS - return will be empty
    /// HOLDS_LST - `strategies` will be a random subset of initialized strategies
    ///             `tokenBalances` will be the user's balances in each token
    /// HOLDS_ETH - `strategies` will only contain BEACON_CHAIN_ETH_STRAT, and
    ///             `tokenBalances` will contain the user's eth balance
    /// HOLDS_MIX - random combination of `HOLDS_LST` and `HOLDS_ETH` 
    function _dealRandAssets(User user, uint assetType) internal returns (IStrategy[] memory, uint[] memory) {

        IStrategy[] memory strategies;
        uint[] memory tokenBalances;

        if (assetType == NO_ASSETS) {
            strategies = new IStrategy[](0);
            tokenBalances = new uint[](0);
        } else if (assetType == HOLDS_LST) {

            // Select a random number of assets
            uint numAssets = _randUint({ min: 1, max: lstStrats.length });

            strategies = new IStrategy[](numAssets);
            tokenBalances = new uint[](numAssets);

            // For each asset, award the user a random balance of the underlying token
            for (uint i = 0; i < numAssets; i++) {
                IStrategy strat = lstStrats[i];
                IERC20 underlyingToken = strat.underlyingToken();
                
                uint balance = _randUint({ min: MIN_BALANCE, max: MAX_BALANCE });
                StdCheats.deal(address(underlyingToken), user.addr(), balance);

                tokenBalances[i] = balance;
                strategies[i] = strat;
            }

            return (strategies, tokenBalances);
        } else if (assetType == HOLDS_ETH) {
            revert("_getRandAssets: HOLDS_ETH unimplemented");
        } else if (assetType == HOLDS_MIX) {
            revert("_getRandAssets: HOLDS_MIX unimplemented");
        } else {
            revert("_getRandAssets: assetType unimplemented");
        }

        return (strategies, tokenBalances);
    }

    /// @dev Uses `random` to return a random uint, with a range given by `min` and `max` (inclusive)
    /// @return `min` <= result <= `max`
    function _randUint(uint min, uint max) internal returns (uint) {        
        uint range = max - min + 1;

        // calculate the number of bits needed for the range
        uint bitsNeeded = 0;
        uint tempRange = range;
        while (tempRange > 0) {
            bitsNeeded++;
            tempRange >>= 1;
        }

        // create a mask for the required number of bits
        // and extract the value from the hash
        uint mask = (1 << bitsNeeded) - 1;
        uint value = uint(random) & mask;

        // in case value is out of range, wrap around or retry
        while (value >= range) {
            value = (value - range) & mask;
        }

        // Hash `random` with itself so the next value we generate is different
        random = keccak256(abi.encodePacked(random));
        return min + value;
    }

    function _randAssetType() internal returns (uint) {
        uint idx = _randUint({ min: 0, max: assetTypes.length - 1 });
        uint assetType = uint(uint8(assetTypes[idx]));

        return assetType;
    }

    function _randSignedType() internal returns (uint) {
        uint idx = _randUint({ min: 0, max: signedTypes.length - 1 });
        uint signedType = uint(uint8(signedTypes[idx]));

        return signedType;
    }  

    /**
     * @dev Converts a bitmap into an array of bytes
     * @dev Each byte in the input is processed as indicating a single bit to flip in the bitmap
     */
    function _bitmapToBytes(uint bitmap) internal returns (bytes memory bytesArray) {
        for (uint i = 0; i < 256; ++i) {
            // Mask for i-th bit
            uint mask = uint(1 << i);

            // emit log_named_uint("mask: ", mask);

            // If the i-th bit is flipped, add a byte to the return array
            if (bitmap & mask != 0) {
                bytesArray = bytes.concat(bytesArray, bytes1(uint8(1 << i)));
            }
        }
        return bytesArray;
    }

    function _printUserInfo(
        uint assetType, 
        uint signedType, 
        IStrategy[] memory strategies, 
        uint[] memory tokenBalances
    ) internal {

        emit log("Creating user:");
        emit log_named_string("assetType: ", assetTypeToStr[assetType]);
        emit log_named_string("signedType: ", signedTypeToStr[signedType]);

        emit log_named_uint("num assets: ", strategies.length);

        for (uint i = 0; i < strategies.length; i++) {
            IStrategy strat = strategies[i];
            IERC20 underlyingToken = strat.underlyingToken();

            emit log_named_string("token name: ", IERC20Metadata(address(underlyingToken)).name());
            emit log_named_uint("token balance: ", tokenBalances[i]);
        }
    }
}