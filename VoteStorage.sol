// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VoteStorage
 * @dev Hợp đồng thông minh đơn giản để lưu trữ các mã hash
 * của phiếu bầu một cách công khai và minh bạch.
 */
contract VoteStorage {
    
    // Mảng lưu trữ tất cả các mã hash phiếu bầu
    string[] public voteHashes;
    
    // Ánh xạ (mapping) để kiểm tra một hash đã tồn tại hay chưa
    mapping(string => bool) private hasBeenRecorded;
    
    // Sự kiện (Event) được phát ra mỗi khi một phiếu được ghi
    event VoteRecorded(string voteHash, uint timestamp, address sender);

    /**
     * @dev Ghi một mã hash phiếu bầu mới vào blockchain.
     * Yêu cầu: Mã hash này phải là duy nhất.
     */
    function storeVote(string memory _voteHash) public {
        // Kiểm tra xem phiếu này đã được ghi trước đó chưa
        require(hasBeenRecorded[_voteHash] == false, "Vote hash already exists");
        
        // Ghi lại phiếu bầu
        voteHashes.push(_voteHash);
        hasBeenRecorded[_voteHash] = true;
        
        // Phát ra sự kiện để thông báo
        emit VoteRecorded(_voteHash, block.timestamp, msg.sender);
    }
    
    /**
     * @dev Lấy tổng số phiếu đã được ghi lại.
     */
    function getVoteCount() public view returns (uint) {
        return voteHashes.length;
    }
}