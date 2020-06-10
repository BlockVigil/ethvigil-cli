pragma solidity ^0.5.7;

contract SignerControlBase {
    event PrimaryOwnerAddition(address indexed owner);
    event SecondaryOwnerAddition(address indexed owner);
    event PrimaryOwnerRemoval(address indexed owner);
    event SecondaryOwnerRemoval(address indexed owner);
    event RequirementChange(uint required);
    ///events related to transactions agreed through this contract
    event TransactionSubmission(uint transactionId);
    event TransactionConfirmation(address indexed sender, uint indexed transactionId);
    event TransactionRevocation(address indexed sender, uint indexed transactionId);
    event TransactionExecution(uint transactionId);
    event TransactionExecutionFailure(uint transactionId);

    uint constant MAX_OWNER_COUNT = 50;
    mapping (address => bool) public isPrimaryOwner;
    mapping (address => bool) public isSecondaryOwner;

    mapping (uint => mapping (address => bool)) public confirmations;
    mapping (uint => Transaction) public transactions;
    mapping (uint => mapping (address => bool)) public transactionConfirmations;
    address[] public primaryOwners;
    address[] public secondaryOwners;
    uint public required_confirmations; // required for signer address modifications and secondary ownership modifications
    uint public requestCount;
    uint public transactionCount;



    ///holds information on transactions to enable safe execution of ownership functions
    struct Transaction {
        address destination;
        uint value;
        bytes data;
        bool executed;
    }


    modifier valid_requirements(uint ownerCount, uint _required) {
        if (   ownerCount > MAX_OWNER_COUNT
        || _required > ownerCount
        || _required == 0
        || ownerCount == 0)
            revert();
        _;
    }

    modifier primaryOwnerDoesNotExist(address owner) {
        if (isPrimaryOwner[owner])
            revert("Primary Owner already exists");
        _;
    }

    modifier primaryOwnerExists(address owner) {
        if (!isPrimaryOwner[owner])
            revert();
        _;
    }

    modifier PrimaryOrSecondaryOwnerExists(address owner) {
        if(!isPrimaryOwner[owner] && !isSecondaryOwner[owner])
            revert('Not an owner');
        _;
    }

    modifier PrimaryOrSecondaryOwnerDoesNotExist(address owner) {
        if(isPrimaryOwner[owner] || isSecondaryOwner[owner])
            revert('Already an owner');
        _;
    }


    modifier onlySignerControl() {
        if (msg.sender != address(this))
            revert("Only SignerControl contract can perform this task");
        _;
    }

    modifier notNull(address _address) {
        if (_address == address(0))
            revert("Null address specified");
        _;
    }


    modifier transactionExists(uint _transactionid) {
        if (transactions[_transactionid].destination == address(0))
            revert("Transaction ID does not exist");
        _;
    }


    modifier transactionNotConfirmed(uint transactionId, address _sender) {
        if (transactionConfirmations[transactionId][_sender])
            revert("Transaction already confirmed");
        _;
    }

    modifier confirmed(uint request_id, address _sender) {
        if (!confirmations[request_id][_sender])
            revert("Request was never confirmed to be revoked");
        _;
    }



    modifier transactionNotExecuted(uint transactionId) {
        if (transactions[transactionId].executed)
            revert("Transaction has already been executed");
        _;
    }


    constructor (address[] memory _primaryOwners, address[] memory _secondaryOwners, uint _required_confirmations)
    public
    valid_requirements(_primaryOwners.length+_secondaryOwners.length, _required_confirmations)
    {
        for (uint i=0; i<_primaryOwners.length; i++) {
            if (isPrimaryOwner[_primaryOwners[i]] || _primaryOwners[i] == address(0))
                revert();
            isPrimaryOwner[_primaryOwners[i]] = true;
        }

        for (uint i=0; i<_secondaryOwners.length; i++) {
            if (isSecondaryOwner[_secondaryOwners[i]] || _secondaryOwners[i] == address(0))
                revert();
            isSecondaryOwner[_secondaryOwners[i]] = true;
        }
        primaryOwners = _primaryOwners;
        secondaryOwners = _secondaryOwners;
        required_confirmations = _required_confirmations;

    }


    /// @dev Allows to add a new primary owner. Transaction has to be sent by prepopulated primary accounts supplied during contract instantiation.
    /// @param newPrimaryOwner Address of new primary owner.
    function addPrimaryOwner(address newPrimaryOwner)
    public
    primaryOwnerExists(msg.sender)
    primaryOwnerDoesNotExist(newPrimaryOwner)
    notNull(newPrimaryOwner)
    valid_requirements(primaryOwners.length + secondaryOwners.length + 1, required_confirmations)
    {
        isPrimaryOwner[newPrimaryOwner] = true;
        primaryOwners.push(newPrimaryOwner);
        emit PrimaryOwnerAddition(newPrimaryOwner);
    }

    /// @dev Allows to remove a primary owner. Transaction has to be sent by an existing primary owner
    /// @param owner Address of owner to be removed
    function removePrimaryOwner(address owner)
    public
    primaryOwnerExists(msg.sender)
    primaryOwnerExists(owner)
    valid_requirements(primaryOwners.length + secondaryOwners.length -1, required_confirmations)
    {
        isPrimaryOwner[owner] = false;
        for (uint i=0; i<primaryOwners.length - 1; i++)
            if (primaryOwners[i] == owner) {
                primaryOwners[i] = primaryOwners[primaryOwners.length - 1];
                break;
            }
        primaryOwners.length -= 1; // this depends on the fact that primaryOwnerExists()
        if (required_confirmations > primaryOwners.length + secondaryOwners.length)
            changeRequirement(primaryOwners.length + secondaryOwners.length);
        emit PrimaryOwnerRemoval(owner);
    }

    /// @dev Allows to change the number of required confirmations. Transaction has to be sent by a primary owner
    /// @param _required Number of required confirmations.
    function changeRequirement(uint _required)
    public
    valid_requirements(primaryOwners.length + secondaryOwners.length, _required)
    {
        if (!isPrimaryOwner[msg.sender])
            revert();
        required_confirmations = _required;
        emit RequirementChange(_required);
    }

    /// @dev Allows to replace a primary  owner with a new owner. Only allowed to be executed by an existing primary owner.
    /// @param owner Address of owner to be replaced.
    /// @param newOwner Address of new owner.
    function replacePrimaryOwner(address owner, address newOwner)
    public
    primaryOwnerExists(msg.sender)
    {
        for (uint i=0; i<primaryOwners.length; i++)
            if (primaryOwners[i] == owner) {
                primaryOwners[i] = newOwner;
                break;
            }
        isPrimaryOwner[owner] = false;
        isPrimaryOwner[newOwner] = true;
        emit PrimaryOwnerRemoval(owner);
        emit PrimaryOwnerAddition(newOwner);
    }

     /// @dev Allows to add a new second owner. Transaction has to be sent only the current instance of SignerControl contract.
    /// @param newSecondaryOwner Address of new secondary owner.
    function addSecondaryOwner(address newSecondaryOwner)
    public
    onlySignerControl
    notNull(newSecondaryOwner)
    valid_requirements(primaryOwners.length + secondaryOwners.length + 1, required_confirmations)
    {
        isSecondaryOwner[newSecondaryOwner] = true;
        secondaryOwners.push(newSecondaryOwner);
        emit SecondaryOwnerAddition(newSecondaryOwner);
    }

    function removeSecondaryOwner(address owner)
    public
    onlySignerControl
    notNull(owner)
    valid_requirements(primaryOwners.length + secondaryOwners.length - 1, required_confirmations)
    {
        isSecondaryOwner[owner] = false;
        for (uint i=0; i<secondaryOwners.length - 1; i++)
            if (secondaryOwners[i] == owner) {
                secondaryOwners[i] = secondaryOwners[secondaryOwners.length - 1];
                break;
            }
        secondaryOwners.length -= 1; // this depends on the fact that primaryOwnerExists()
        if (required_confirmations > primaryOwners.length + secondaryOwners.length)
            changeRequirement(primaryOwners.length + secondaryOwners.length);
        emit SecondaryOwnerRemoval(owner);
    }

    /*
    MultiSig Wallet Transaction submission and confirmation logic begins here
    These enable the safe execution of ownership functions over the contract
    */

    /// @dev Allows an owner to submit and confirm a transaction.
    /// @param destination Transaction target address.
    /// @param value Transaction ether value.
    /// @param data Transaction data payload.
    /// @return Returns transaction ID.
    function submitTransaction(address destination, uint value, bytes memory data)
        public
        returns (uint transactionId)
    {
        transactionId = addTransaction(destination, value, data);
        confirmTransaction(transactionId);
    }

    /// @dev Allows an owner to confirm a transaction.
    /// @param transactionId Transaction ID.
    function confirmTransaction(uint transactionId)
        public
        PrimaryOrSecondaryOwnerExists(msg.sender)
        transactionExists(transactionId)
        transactionNotConfirmed(transactionId, msg.sender)
    {
        transactionConfirmations[transactionId][msg.sender] = true;
        emit TransactionConfirmation(msg.sender, transactionId);
        executeTransaction(transactionId);
    }

    /// @dev Allows anyone to execute a confirmed transaction.
    /// @param transactionId Transaction ID.
    function executeTransaction(uint transactionId)
        public
        transactionNotExecuted(transactionId)
    {
        if (isConfirmedTransaction(transactionId)) {
            Transaction storage temptx = transactions[transactionId];
            temptx.executed = true;
            (bool success, bytes memory data) = temptx.destination.call.value(temptx.value)(temptx.data);
            if (success)
                emit TransactionExecution(transactionId);
            else {
                emit TransactionExecutionFailure(transactionId);
                temptx.executed = false;
            }
        }
    }

    /// @dev Returns the confirmation status of a transaction.
    /// @param transactionId Transaction ID.
    /// @return Confirmation status.
    function isConfirmedTransaction(uint transactionId)
        public
        view
        returns (bool)
    {
        uint count = 0;
        for (uint i=0; i<secondaryOwners.length; i++) {
            if (transactionConfirmations[transactionId][secondaryOwners[i]])
                count += 1;
            if (count == required_confirmations)
                return true;
        }
        // if secondary owners havent done their bit yet
        for (uint i=0; i<primaryOwners.length; i++) {
            if (transactionConfirmations[transactionId][primaryOwners[i]])
                count += 1;
            if (count == required_confirmations)
                return true;
        }
    }

    /*
     * Internal functions
     */
    /// @dev Adds a new transaction to the transaction mapping, if transaction does not exist yet.
    /// @param destination Transaction target address.
    /// @param value Transaction ether value.
    /// @param data Transaction data payload.
    /// @return Returns transaction ID.
    function addTransaction(address destination, uint value, bytes memory data)
        internal
        notNull(destination)
        returns (uint transactionId)
    {
        transactionId = transactionCount;
        transactions[transactionId] = Transaction({
            destination: destination,
            value: value,
            data: data,
            executed: false
        });
        transactionCount += 1;
        emit TransactionSubmission(transactionId);
    }

    /*
    Utility public functions
    */

    /// @dev Get primary owners.
    /// @return List of primary owner addresses.
    function getPrimaryOwners()
        public
        view
        returns (address[] memory)
    {
        return primaryOwners;
    }

    /// @dev Get secondary owners.
    /// @return List of secondary owner addresses.
    function getSecondaryOwners()
        public
        view
        returns (address[] memory)
    {
        return secondaryOwners;
    }

    /*
    Transaction features
    */

    /// @dev Returns number of confirmations of a transaction.
    /// @param transactionId Transaction ID.
    /// @return Number of confirmations.
    function getTransactionConfirmationCount(uint transactionId)
        public
        returns (uint count)
    {
        for (uint i=0; i<primaryOwners.length; i++)
            if (transactionConfirmations[transactionId][primaryOwners[i]])
                count += 1;

        for (uint i=0; i<secondaryOwners.length; i++)
            if (transactionConfirmations[transactionId][secondaryOwners[i]])
                count += 1;
    }

    /// @dev Returns total number of transactions after filers are applied.
    /// @param pending Include pending transactions.
    /// @param executed Include executed transactions.
    /// @return Total number of transactions after filters are applied.
    function getTransactionCount(bool pending, bool executed)
        public
        returns (uint count)
    {
        for (uint i=0; i<transactionCount; i++)
            if (   pending && !transactions[i].executed
                || executed && transactions[i].executed)
                count += 1;
    }

    /// @dev Returns array with owner addresses, which confirmed transaction.
    /// @param transactionId Transaction ID.
    /// @return Returns array of owner addresses.
    function getTransactionConfirmations(uint transactionId)
        public
        returns (address[] memory _confirmations)
    {
        address[] memory confirmationsTemp = new address[](primaryOwners.length + secondaryOwners.length);
        uint count = 0;
        uint i;
        // go through secondaryOwners
        for (i=0; i<secondaryOwners.length; i++)
            if (transactionConfirmations[transactionId][secondaryOwners[i]]) {
                confirmationsTemp[count] = secondaryOwners[i];
                count += 1;
            }
        // go through primaryOwners
        for (i=0; i<primaryOwners.length; i++)
            if (transactionConfirmations[transactionId][primaryOwners[i]]) {
                confirmationsTemp[count] = primaryOwners[i];
                count += 1;
            }
        _confirmations = new address[](count);
        for (i=0; i<count; i++)
            _confirmations[i] = confirmationsTemp[i];
    }

    /// @dev Returns list of transaction IDs in defined range.
    /// @param from Index start position of transaction array.
    /// @param to Index end position of transaction array.
    /// @param pending Include pending transactions.
    /// @param executed Include executed transactions.
    /// @return Returns array of transaction IDs.
    function getTransactionIds(uint from, uint to, bool pending, bool executed)
        public
        returns (uint[] memory _transactionIds)
    {
        uint[] memory transactionIdsTemp = new uint[](transactionCount);
        uint count = 0;
        uint i;
        for (i=0; i<transactionCount; i++)
            if (   pending && !transactions[i].executed
                || executed && transactions[i].executed)
            {
                transactionIdsTemp[count] = i;
                count += 1;
            }
        _transactionIds = new uint[](to - from);
        for (i=from; i<to; i++)
            _transactionIds[i - from] = transactionIdsTemp[i];
    }

}
