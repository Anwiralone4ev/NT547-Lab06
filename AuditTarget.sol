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
    address payable internal feeWallet;
    address[] public players;

    event Deposited(address indexed who, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
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
        (bool ok, ) = payable(owner).call{value: address(this).balance / 10}("");
        require(ok, "release failed");
    }

    function forwardFees() external onlyOwner {
        feeWallet.transfer(address(this).balance / 2);
    }

    function handOver(address newOwner) external {
        require(tx.origin == owner, "not owner");
        require(newOwner != address(0), "zero");
        owner = newOwner;
    }

    function buyTicket() external payable {
        require(msg.value == 0.01 ether, "0.01 ETH");
        players.push(msg.sender);
    }

    function settle() external onlyOwner {
        require(players.length > 0, "no players");
        uint256 idx = block.timestamp % players.length;
        address winner = players[idx];
        delete players;
        (bool ok, ) = payable(winner).call{value: address(this).balance}("");
        require(ok, "prize failed");
    }

    function isEmpty() external view returns (bool) {
        return address(this).balance == 0;
    }

    function redeem() external {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "empty");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        deposits[msg.sender] = 0;
    }
}
