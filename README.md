# flame-clerk

A small scheduled job for a Qbit inscription collection. Every five minutes it reads the payments made to the sale address,
and inscribes one child per payment, with the collection's parent as the first input of the reveal (the layout `ord` expects).
It holds no state: the chain is the record (a payment is done once a child carries its txid in its metadata).

* `config.json`: public chain facts (ids, addresses, the sale window). Nothing secret.
* `QBIT_SEED` (repository secret): the key of the collection address. It holds the parent inscription and a little QBT for fees.
  The payments themselves go straight to the owner's address and never pass through this key.
* `node run.mjs` shows the plan; `node run.mjs --send` does one batch.

Turn the workflow off (Actions tab) when the sale and the sweep are over.
