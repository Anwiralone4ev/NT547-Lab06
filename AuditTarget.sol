// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// NT547 - Lab 06 - Hop dong rieng cua MSSV 25520656. KHONG deploy len mainnet.

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract PiggyBank_0656 {
    address public owner;
    mapping(address => uint256) public deposits;
    uint256 public nextRelease;
    address payable internal immutable feeWallet;
    address[] public players;
    bytes32 public seedCommit;
    uint256 public salesEnd;

    event Deposited(address indexed who, uint256 amount);

    modifier onlyOwner() {
        require(tx.origin == owner, "not owner");
        _;
    }

    constructor(address payable _feeWallet) {
        require(_feeWallet != address(0), "zero fee wallet");
        owner = msg.sender;
        feeWallet = _feeWallet;
    }

    function save() external payable {
        deposits[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function ownerWithdraw(uint256 amount) external onlyOwner {
        (bool ok, ) = payable(owner).call{value: amount}("");
        require(ok, "withdraw failed");
    }

    function releaseTenth() external onlyOwner {
        require(block.timestamp >= nextRelease, "locked");
        nextRelease = block.timestamp + 1 days;
        (bool ok, ) = payable(owner).call{value: address(this).balance / 10}(
            ""
        );
        require(ok, "release failed");
    }

    function forwardFees() external onlyOwner {
        feeWallet.transfer(address(this).balance / 2);
    }

    function handOver(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero");
        owner = newOwner;
    }

    function openRound(bytes32 commit, uint256 duration) external onlyOwner {
        require(players.length == 0, "round active");
        seedCommit = commit;
        salesEnd = block.timestamp + duration;
    }

    function buyTicket() external payable {
        require(block.timestamp < salesEnd, "sales closed");
        require(msg.value == 0.01 ether, "0.01 ETH");
        players.push(msg.sender);
    }

    function settle(bytes32 seed) external onlyOwner {
        require(block.timestamp >= salesEnd, "sales open");
        require(players.length > 0, "no players");
        require(keccak256(abi.encode(seed)) == seedCommit, "bad seed");
        uint256 idx = uint256(keccak256(abi.encode(seed, players))) %
            players.length;
        address winner = players[idx];
        uint256 prize = players.length * 0.01 ether; // chỉ trả tiền vé
        delete players;
        (bool ok, ) = payable(winner).call{value: prize}("");
        require(ok, "prize failed");
    }

    function isEmpty() external view returns (bool) {
        // slither-disable-next-line incorrect-equality
        return address(this).balance == 0;
    }

    function redeem() external {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "empty");
        deposits[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}
