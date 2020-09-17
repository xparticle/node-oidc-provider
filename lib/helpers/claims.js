const { strict: assert } = require('assert');

const instance = require('./weak_cache');
const pick = require('./_/pick');
const merge = require('./_/merge');
const isPlainObject = require('./_/is_plain_object');

module.exports = function getClaims(provider) {
  const {
    claims: claimConfig, claimsSupported, scopes, dynamicScopes, pairwiseIdentifier,
  } = instance(provider).configuration();

  return class Claims {
    constructor(available, { ctx, client = ctx ? ctx.oidc.client : undefined }) {
      console.log(`claims constructor called with: ${JSON.stringify(available)}`)
      assert.equal(
        typeof available, 'object',
        'expected claims to be an object, are you sure claims() method resolves with or returns one?',
      );
      assert(client instanceof provider.Client, 'second argument must be a Client instance');
      this.available = available;
      this.client = client;
      this.ctx = ctx;
      this.filter = {};
    }

    scope(value = '') {
      assert(!Object.keys(this.filter).length, 'scope cannot be assigned after mask has been set');
      value.split(' ').forEach((scope) => {
        if (!scopes.has(scope)) {
          for (const dynamic of dynamicScopes) { // eslint-disable-line no-restricted-syntax
            if (dynamic.test(scope)) {
              scope = dynamic; // eslint-disable-line no-param-reassign
              break;
            }
          }
        }

        this.mask(claimConfig.get(scope));
      });
      return this;
    }

    mask(value) {
      merge(this.filter, value);
    }

    rejected(value = []) {
      value.forEach((claim) => {
        delete this.filter[claim];
      });
    }

    async result() {
      const { available } = this;
      console.log(`claims result will work with available,${JSON.stringify(available)} and filter, ${JSON.stringify(this.filter)}`)

      const include = Object.entries(this.filter)
        .map(([key, value]) => {
          if (value === null || isPlainObject(value)) {
            return key;
          }

          return undefined;
        })
        .filter((key) => key && claimsSupported.has(key));
      console.log(`claims include : ${JSON.stringify(include)}`)
      const claims = pick(available, ...include);
      console.log(`claims after picking: ${JSON.stringify(claims)}`)
      if (available._claim_names && available._claim_sources) {
        console.log(`available claims names and sources found, ${JSON.stringify(available._claim_names)}, ${JSON.stringify(available._claim_sources)}`)
        claims._claim_names = pick(available._claim_names, ...include);
        console.log(`claims with names , ${JSON.stringify(claims)}`)
        claims._claim_sources = pick(
          available._claim_sources,
          ...Object.values(claims._claim_names),
        );
        console.log(`claims with sources , ${JSON.stringify(claims)}`)
        if (!Object.keys(claims._claim_names).length) {
          delete claims._claim_names;
          delete claims._claim_sources;
        }
        console.log(`claims after weeding , ${JSON.stringify(claims)}`)
      }

      if (this.client.sectorIdentifier && claims.sub) {
        console.log(`what is sectoridentifier? , ${JSON.stringify(this.client.sectorIdentifier)}`)
        claims.sub = await pairwiseIdentifier(this.ctx, claims.sub, this.client);
      }
      console.log(`claims to be returned , ${JSON.stringify(claims)}`)
      return claims;
    }
  };
};
