// Copyright 2019-2022 Unique Network (Gibraltar) Ltd.
// This file is part of Unique Network.

// Unique Network is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Unique Network is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Unique Network. If not, see <http://www.gnu.org/licenses/>.

import {default as usingApi} from './substrate/substrate-api';
import chai from 'chai';
import {IKeyringPair} from '@polkadot/types/types';
import {
  createCollectionExpectSuccess,
  createItemExpectSuccess,
  addCollectionAdminExpectSuccess,
  createCollectionWithPropsExpectSuccess,
  createItemWithPropsExpectSuccess,
  createItemWithPropsExpectFailure,
} from './util/helpers';

const expect = chai.expect;
let alice: IKeyringPair;
let bob: IKeyringPair;

describe('integration test: ext. ():', () => {
  before(async () => {
    await usingApi(async (api, privateKeyWrapper) => {
      alice = privateKeyWrapper('//Alice');
      bob = privateKeyWrapper('//Bob');
    });
  });

  it('Create new item in NFT collection', async () => {
    const createMode = 'NFT';
    const newCollectionID = await createCollectionExpectSuccess({mode: {type: createMode}});
    await createItemExpectSuccess(alice, newCollectionID, createMode);
  });
  it('Create new item in Fungible collection', async () => {
    const createMode = 'Fungible';
    const newCollectionID = await createCollectionExpectSuccess({mode: {type: createMode, decimalPoints: 0}});
    await createItemExpectSuccess(alice, newCollectionID, createMode);
  });
  it('Create new item in ReFungible collection', async () => {
    const createMode = 'ReFungible';
    const newCollectionID = await createCollectionExpectSuccess({mode: {type: createMode}});
    await createItemExpectSuccess(alice, newCollectionID, createMode);
  });
  it('Create new item in NFT collection with collection admin permissions', async () => {
    const createMode = 'NFT';
    const newCollectionID = await createCollectionExpectSuccess({mode: {type: createMode}});
    await addCollectionAdminExpectSuccess(alice, newCollectionID, bob.address);
    await createItemExpectSuccess(bob, newCollectionID, createMode);
  });
  it('Create new item in Fungible collection with collection admin permissions', async () => {
    const createMode = 'Fungible';
    const newCollectionID = await createCollectionExpectSuccess({mode: {type: createMode, decimalPoints: 0}});
    await addCollectionAdminExpectSuccess(alice, newCollectionID, bob.address);
    await createItemExpectSuccess(bob, newCollectionID, createMode);
  });
  it('Create new item in ReFungible collection with collection admin permissions', async () => {
    const createMode = 'ReFungible';
    const newCollectionID = await createCollectionExpectSuccess({mode: {type: createMode}});
    await addCollectionAdminExpectSuccess(alice, newCollectionID, bob.address);
    await createItemExpectSuccess(bob, newCollectionID, createMode);
  });

  it('Set property Admin', async () => {
    const createMode = 'NFT';
    const newCollectionID = await createCollectionWithPropsExpectSuccess({mode: {type: createMode}, 
      propPerm:   [{key: 'k', permission: {mutable: true, collectionAdmin: true, tokenOwner: false}}]});
    
    await createItemWithPropsExpectSuccess(alice, newCollectionID, createMode, [{key: 'k', value: 't2'}]);
  });

  it('Set property AdminConst', async () => {
    const createMode = 'NFT';
    const newCollectionID = await createCollectionWithPropsExpectSuccess({mode: {type: createMode}, 
      propPerm:   [{key: 'key1', permission: {mutable: false, collectionAdmin: true, tokenOwner: false}}]});
    
    await createItemWithPropsExpectSuccess(alice, newCollectionID, createMode, [{key: 'key1', value: 'val1'}]);
  });

  it('Set property itemOwnerOrAdmin', async () => {
    const createMode = 'NFT';
    const newCollectionID = await createCollectionWithPropsExpectSuccess({mode: {type: createMode},
      propPerm:   [{key: 'key1', permission: {mutable: true, collectionAdmin: true, tokenOwner: true}}]});
    
    await createItemWithPropsExpectSuccess(alice, newCollectionID, createMode, [{key: 'key1', value: 'val1'}]);
  });
});

describe('Negative integration test: ext. createItem():', () => {
  before(async () => {
    await usingApi(async (api, privateKeyWrapper) => {
      alice = privateKeyWrapper('//Alice');
      bob = privateKeyWrapper('//Bob');
    });
  });

  it('Regular user cannot create new item in NFT collection', async () => {
    const createMode = 'NFT';
    const newCollectionID = await createCollectionExpectSuccess({mode: {type: createMode}});
    await expect(createItemExpectSuccess(bob, newCollectionID, createMode)).to.be.rejected;
  });
  it('Regular user cannot create new item in Fungible collection', async () => {
    const createMode = 'Fungible';
    const newCollectionID = await createCollectionExpectSuccess({mode: {type: createMode, decimalPoints: 0}});
    await expect(createItemExpectSuccess(bob, newCollectionID, createMode)).to.be.rejected;
  });
  it('Regular user cannot create new item in ReFungible collection', async () => {
    const createMode = 'ReFungible';
    const newCollectionID = await createCollectionExpectSuccess({mode: {type: createMode}});
    await expect(createItemExpectSuccess(bob, newCollectionID, createMode)).to.be.rejected;
  });

  it('No editing rights', async () => {
    await usingApi(async () => {
      const createMode = 'NFT';
      const newCollectionID = await createCollectionWithPropsExpectSuccess({mode: {type: createMode}, 
        propPerm:   [{key: 'key1', permission: {mutable: false, collectionAdmin: false, tokenOwner: false}}]});
      await addCollectionAdminExpectSuccess(alice, newCollectionID, bob.address);

      await createItemWithPropsExpectFailure(bob, newCollectionID, 'NFT', [{key: 'key1', value: 'v'}]);
    });
  });

  it('User doesnt have editing rights', async () => {
    await usingApi(async () => {
      const newCollectionID = await createCollectionWithPropsExpectSuccess({propPerm: [{key: 'key1', permission: {mutable: true, collectionAdmin: false, tokenOwner: false}}]});
      await createItemWithPropsExpectFailure(bob, newCollectionID, 'NFT', [{key: 'key1', value: 'v'}]);
    });
  });

  it('Adding property without access rights', async () => {
    await usingApi(async () => {
      const newCollectionID = await createCollectionWithPropsExpectSuccess();
      await addCollectionAdminExpectSuccess(alice, newCollectionID, bob.address);

      await createItemWithPropsExpectFailure(bob, newCollectionID, 'NFT', [{key: 'k', value: 'v'}]);
    });
  });

  it('Adding more than 64 prps', async () => {
    await usingApi(async () => {
      const prps = [];

      for (let i = 0; i < 65; i++) {
        prps.push({key: `key${i}`, value: `value${i}`});
      }

      const newCollectionID = await createCollectionWithPropsExpectSuccess();
      
      await createItemWithPropsExpectFailure(alice, newCollectionID, 'NFT', prps);
    });
  });

  it('Trying to add bigger property than allowed', async () => {
    await usingApi(async () => {
      const newCollectionID = await createCollectionWithPropsExpectSuccess();
      
      await createItemWithPropsExpectFailure(alice, newCollectionID, 'NFT', [{key: 'k', value: 'vvvvvv'.repeat(5000)}, {key: 'k2', value: 'vvv'.repeat(5000)}]);
    });
  });
});
