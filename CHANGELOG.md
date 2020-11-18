# Changelog

## 0.4.3 (2020-11-19)

* general maintenance and removal of bitrot.
* Pin protolude to 0.3.x to prevent further breakage due to changes in
  protolude.

## 0.4.2 (2018-01-22)

* Minor release to allow docs to be generated on Hackage.

## 0.4.1 (2018-01-17)

* Fixed potential security issue in Ed25519 (see
  https://github.com/jml/haskell-spake2/pull/16), present since
  initial release. Please update as soon as possible.

## 0.4.0 (2017-11-22)

* Change `createSessionKey` inputs to be `inbound`, `outbound` rather than
  `side A`, `side B`. If you were passing as `side A`, `side B` before, it
  should continue to work, unless you were deliberately triggering an error
  condition.
* Add `spake2Exchange`, for much more convenient exchanges.

## 0.3.0 (2017-11-11)

* Depend on protolude 0.2 minimum

## 0.2.0 (2017-06-08)

* `Group` typeclass split into `Group` and `AbelianGroup` typeclasses

## 0.1.0 (2017-05-28)

Initial release
