//      

import _assert from 'assert'

export const assert = (v     , m         ) => {
  _assert.ok(v, m)
  console.log('\x1b[32m%s\x1b[0m','PASS @', m)
}
