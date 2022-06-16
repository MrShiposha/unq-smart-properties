// SPDX-License-Identifier: OTHER
// This code is automatically generated

pragma solidity >=0.8.0 <0.9.0;

// Common stubs holder
interface Dummy {

}

interface ERC165 is Dummy {
	function supportsInterface(bytes4 interfaceID) external view returns (bool);
}

// Inline
interface CollectionHelpersEvents {
	event CollectionCreated(
		address indexed owner,
		address indexed collectionId
	);
}

// Selector: 6432f605
interface CollectionHelpers is Dummy, ERC165, CollectionHelpersEvents {
	// Selector: createNonfungibleCollection(string,string,string) e34a6844
	function createNonfungibleCollection(
		string memory name,
		string memory description,
		string memory tokenPrefix
	) external view returns (address);

	// Selector: createRefungibleCollection(string,string,string) 44a68ad5
	function createRefungibleCollection(
		string memory name,
		string memory description,
		string memory tokenPrefix
	) external view returns (address);

	// Selector: isCollectionExist(address) c3de1494
	function isCollectionExist(address collectionAddress)
		external
		view
		returns (bool);
}
