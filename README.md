## Remote Ed25519 RPC Signer

An Ed25519 Remote RPC Signer implementation in Rust, using [Zcash's ZIP215 validation rules](https://zips.z.cash/zip-0215) via the `ed25519-zebra >= 2` crate.

It can be used to offload Coordinator Milestone's signature generation to third-party machines, mitigating the risk of private key exposure by compromise of a single machine.

## Design

The project is divided into two components: a `dispatcher` and a `signer`. The `dispatcher` is the sole endpoint that Coordinator implementations will use, it does not hold any private key material, and it simply maps requests to the `signer` services holding the corresponding private key.
The `signer` service receives the message to be signed, and generates signatures according to the public keys requested, if an exact match is found. 

The `dispatcher` and `signer` authenticate each other using TLS mutual authentication.

## RPC Definition
### Dispatcher
```
syntax = "proto3";
package dispatcher;

service SignatureDispatcher {

  rpc SignMilestone (SignMilestoneRequest) returns (SignMilestoneResponse);

}

message SignMilestoneRequest {

  repeated bytes pubKeys = 1;
  bytes msEssence = 2;

}

message SignMilestoneResponse {

  repeated bytes signatures = 1;

}
```
### Signer
```
syntax = "proto3";
package signer;

service Signer {

  rpc SignWithKey (SignWithKeyRequest) returns (SignWithKeyResponse);

}

message SignWithKeyRequest {

  bytes pubKey = 1;
  bytes msEssence = 2;

}

message SignWithKeyResponse {

  bytes signature = 1;

}
```

## Example configuration
### Dispatcher
The `dispatcher` simply maps public keys to the `signer` endpoint holding the corresponding private key.

```json
{
  "bind_addr": "0.0.0.0:50051",
  "signers": [
    {
      "pubkey":  "268783e7277c7c9f6dc898d08f5ca458941de2eb339e7da948239cc3647dffcc",
      "endpoint": "http://signer1.remote-signer:50052"
    },
    {
      "pubkey":  "d578d0a8e5392040cf5c3ba0153c28c300d8eaed3d8d7ef43729cadfe1e2467b",
      "endpoint": "http://signer2.remote-signer:50053"
    }
  ],
  "tlsauth": {
    "ca": "ssl/ca.crt",
    "client_cert": "ssl/dispatcher.remote-signer.crt",
    "client_key": "ssl/dispatcher.remote-signer_plain.key"
  }
}
```

### Signer
On the other hand the `signer` holds the private key material corresponding to mapped public keys.

```json

{
  "bind_addr": "0.0.0.0:50052",
  "keys": [
    {
      "pubkey":  "268783e7277c7c9f6dc898d08f5ca458941de2eb339e7da948239cc3647dffcc",
      "privkey": "[REDACTED]"
    }
  ],
  "tls": {
    "ca": "ssl/ca.crt",
    "cert": "ssl/signer1.remote-signer.crt",
    "key": "ssl/signer1.remote-signer_plain.key"
  }
}
```

```json
{
  "bind_addr": "0.0.0.0:50053",
  "keys": [
    {
      "pubkey":  "d578d0a8e5392040cf5c3ba0153c28c300d8eaed3d8d7ef43729cadfe1e2467b",
      "privkey": "[REDACTED]"
    }
  ],
  "tls": {
    "ca": "ssl/ca.crt",
    "cert": "ssl/signer2.remote-signer.crt",
    "key": "ssl/signer2.remote-signer_plain.key"
  }
}
```
