//
// This file is subject to the terms and conditions defined in
// file 'LICENSE', which is part of this source code package.
//

import {IKeyringPair} from '@polkadot/types/types';
import privateKey from './substrate/privateKey';
import usingApi from './substrate/substrate-api';
import {
  addToAllowListExpectSuccess,
  createCollectionExpectSuccess,
  createItemExpectFailure,
  createItemExpectSuccess,
  enableAllowListExpectSuccess,
  setMintPermissionExpectSuccess,
  addCollectionAdminExpectSuccess,
  disableAllowListExpectSuccess,
} from './util/helpers';

describe('Integration Test public minting', () => {
  let alice: IKeyringPair;
  let bob: IKeyringPair;

  before(async () => {
    await usingApi(async () => {
      alice = privateKey('//Alice');
      bob = privateKey('//Bob');
    });
  });

  it('If the AllowList mode is enabled, then the address added to the allowlist and not the owner or administrator can create tokens', async () => {
    await usingApi(async () => {
      const collectionId = await createCollectionExpectSuccess({mode: {type: 'NFT'}});
      await enableAllowListExpectSuccess(alice, collectionId);
      await setMintPermissionExpectSuccess(alice, collectionId, true);
      await addToAllowListExpectSuccess(alice, collectionId, bob.address);

      await createItemExpectSuccess(bob, collectionId, 'NFT');
    });
  });

  it('If the AllowList mode is enabled, address not included in allowlist that is regular user cannot create tokens', async () => {
    await usingApi(async () => {
      const collectionId = await createCollectionExpectSuccess({mode: {type: 'NFT'}});
      await enableAllowListExpectSuccess(alice, collectionId);
      await setMintPermissionExpectSuccess(alice, collectionId, true);
      await createItemExpectFailure(bob, collectionId, 'NFT');
    });
  });

  it('If the AllowList mode is enabled, address not included in allowlist that is admin can create tokens', async () => {
    await usingApi(async () => {
      const collectionId = await createCollectionExpectSuccess({mode: {type: 'NFT'}});
      await enableAllowListExpectSuccess(alice, collectionId);
      await setMintPermissionExpectSuccess(alice, collectionId, true);
      await addCollectionAdminExpectSuccess(alice, collectionId, bob.address);
      await createItemExpectSuccess(bob, collectionId, 'NFT');
    });
  });

  it('If the AllowList mode is enabled, address not included in allowlist that is owner can create tokens', async () => {
    await usingApi(async () => {
      const collectionId = await createCollectionExpectSuccess({mode: {type: 'NFT'}});
      await enableAllowListExpectSuccess(alice, collectionId);
      await setMintPermissionExpectSuccess(alice, collectionId, true);
      await createItemExpectSuccess(alice, collectionId, 'NFT');
    });
  });

  it('If the AllowList mode is disabled, owner can create tokens', async () => {
    await usingApi(async () => {
      const collectionId = await createCollectionExpectSuccess({mode: {type: 'NFT'}});
      await disableAllowListExpectSuccess(alice, collectionId);
      await setMintPermissionExpectSuccess(alice, collectionId, true);
      await createItemExpectSuccess(alice, collectionId, 'NFT');
    });
  });

  it('If the AllowList mode is disabled, collection admin can create tokens', async () => {
    await usingApi(async () => {
      const collectionId = await createCollectionExpectSuccess({mode: {type: 'NFT'}});
      await disableAllowListExpectSuccess(alice, collectionId);
      await setMintPermissionExpectSuccess(alice, collectionId, true);
      await addCollectionAdminExpectSuccess(alice, collectionId, bob.address);
      await createItemExpectSuccess(bob, collectionId, 'NFT');
    });
  });

  it('If the AllowList mode is disabled, regular user can`t create tokens', async () => {
    await usingApi(async () => {
      const collectionId = await createCollectionExpectSuccess({mode: {type: 'NFT'}});
      await disableAllowListExpectSuccess(alice, collectionId);
      await setMintPermissionExpectSuccess(alice, collectionId, true);
      await createItemExpectFailure(bob, collectionId, 'NFT');
    });
  });
});

describe('Integration Test private minting', () => {
  let alice: IKeyringPair;
  let bob: IKeyringPair;

  before(async () => {
    await usingApi(async () => {
      alice = privateKey('//Alice');
      bob = privateKey('//Bob');
    });
  });

  it('Address that is the not owner or not admin cannot create tokens', async () => {
    await usingApi(async () => {
      const collectionId = await createCollectionExpectSuccess({mode: {type: 'NFT'}});
      await enableAllowListExpectSuccess(alice, collectionId);
      await setMintPermissionExpectSuccess(alice, collectionId, false);
      await addToAllowListExpectSuccess(alice, collectionId, bob.address);
      await createItemExpectFailure(bob, collectionId, 'NFT');
    });
  });

  it('Address that is collection owner can create tokens', async () => {
    await usingApi(async () => {
      const collectionId = await createCollectionExpectSuccess({mode: {type: 'NFT'}});
      await disableAllowListExpectSuccess(alice, collectionId);
      await setMintPermissionExpectSuccess(alice, collectionId, false);
      await createItemExpectSuccess(alice, collectionId, 'NFT');
    });
  });

  it('Address that is admin can create tokens', async () => {
    await usingApi(async () => {
      const collectionId = await createCollectionExpectSuccess({mode: {type: 'NFT'}});
      await disableAllowListExpectSuccess(alice, collectionId);
      await setMintPermissionExpectSuccess(alice, collectionId, false);
      await addCollectionAdminExpectSuccess(alice, collectionId, bob.address);
      await createItemExpectSuccess(bob, collectionId, 'NFT');
    });
  });
});
