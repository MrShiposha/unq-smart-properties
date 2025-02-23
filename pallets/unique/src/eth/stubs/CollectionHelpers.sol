// SPDX-License-Identifier: OTHER
// This code is automatically generated

pragma solidity >=0.8.0 <0.9.0;

// Common stubs holder
contract Dummy {
	uint8 dummy;
	string stub_error = "this contract is implemented in native";
}

contract ERC165 is Dummy {
	function supportsInterface(bytes4 interfaceID)
		external
		view
		returns (bool)
	{
		require(false, stub_error);
		interfaceID;
		return true;
	}
}

// Inline
contract CollectionHelpersEvents {
	event CollectionCreated(
		address indexed owner,
		address indexed collectionId
	);
}

// Selector: 20947cd0
contract CollectionHelpers is Dummy, ERC165, CollectionHelpersEvents {
	// Selector: createNonfungibleCollection(string,string,string) e34a6844
	function createNonfungibleCollection(
		string memory name,
		string memory description,
		string memory tokenPrefix
	) public view returns (address) {
		require(false, stub_error);
		name;
		description;
		tokenPrefix;
		dummy;
		return 0x0000000000000000000000000000000000000000;
	}

	// Selector: isCollectionExist(address) c3de1494
	function isCollectionExist(address collectionAddress)
		public
		view
		returns (bool)
	{
		require(false, stub_error);
		collectionAddress;
		dummy;
		return false;
	}
}
