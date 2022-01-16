# cosign-gatekeeper-provider
To integrate [OPA Gatekeeper's new ExternalData feature](https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata) with [cosign](github.com/sigstore/cosign) to determine whether the images  are valid by verifying its signatures

> This repo is meant for testing Gatekeeper external data feature. Do not use for production.

## Installation

- Deploy Gatekeeper with external data enabled (`--enable-external-data`)
```sh
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper/gatekeeper  \
    --name-template=gatekeeper \
    --namespace gatekeeper-system --create-namespace \
    --set enableExternalData=true \
    --set controllerManager.dnsPolicy=ClusterFirst,audit.dnsPolicy=ClusterFirst
```

Let's install the `cosign-gatekeeper-provider`:

 `kubectl apply -f manifest`

- `kubectl apply -f manifest/provider.yaml`
  - > Update `url` if it's not `http://cosign-gatekeeper-provider.cosign-gatekeeper-provider:8090` (default)

- `kubectl apply -f policy/template.yaml`

- `kubectl apply -f policy/constraint.yaml`

## Verification

To test this successfully, we should sign one of our images with [cosign](https://github.com/sigstore/cosign#installation) tool.

We have two files under `policy/examples`, one for valid manifest that contains signed image, the other is invalid. To do the same you should sign your image as I did:

```shell
$ crane copy alpine:latest devopps/alpine:signed
$ crane copy alpine:3.14 devopps/alpine:unsigned
$ COSIGN_EXPERIMENTAL=1 cosign sign devopps/signed:latest
```

So, once you are ready, let's apply these manifests one by one. It should allow deploying Pod for valid.yaml, and deny for the other one.

## Configuration

By default, the provider verifies images against `https://rekor.sigstore.dev`
with the Fulcio roots.

You can configure the list of verifiers by passing a configuration file with
the `-config-file=<file>` flag.

For example:

```yaml
verifiers:
  - options:
      key: "gcpkms://projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key"

  - options:
      key: "/cosign.pub"

  - options:
      key: |-
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERe5B6LSgARjUVg4TwTwhlcUP0+pC
        hunFRFW/e35eK5KQ3ju6yJpVuypEqVvkD5sIRoTyQeTbkk1QVvJHZ2aDXQ==
        -----END PUBLIC KEY-----

  # Your own rekor server. The root certificates can also be configured with
  # the SIGSTORE_ROOT_FILE environment variable.
  - options:
      rekorURL: "https://rekor.my-org.net"

  # With no options, uses https://rekor.sigstore.dev and the Fulcio roots 
  - name: default
```

## Response

Here's an example of the response structure:

<details>
  <summary>Click to expand</summary>

  ```
  {
    "apiVersion": "externaldata.gatekeeper.sh/v1alpha1",
    "kind": "ProviderResponse",
    "response": {
      "items": [
        {
          "key": "my-registry/foobar:latest",
          "value": {
            "signatures": [
              {
                "id": {
                  "key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFbGNvM3kvUjIzaXI3NnBDWnVWRTNPdjdUMC9kawo0Z0plNFd5Tk4xRzh5VmhpelAvaTc1MUdrZHZqTmZMQmZoVnFkc2xSVzhHWGRXakNqK2lXNTY1cHJnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
                },
                "payload": {
                  "critical": {
                    "identity": {
                      "docker-reference": "my-registry/foobar"
                    },
                    "image": {
                      "docker-manifest-digest": "sha256:3b2c249b772868bcfba7e4389dffe22fe5a7074c2d4b3cff777e860aacf76fbc"
                    },
                    "type": "cosign container image signature"
                  },
                  "optional": null
                },
                "verified": true
              },
              {
                "id": {
                  "iss": "https://github.com/login/oauth",
                  "sub": "my-email@my-domain.com"
                },
                "payload": {
                  "critical": {
                    "identity": {
                      "docker-reference": "my-registry/foobar"
                    },
                    "image": {
                      "docker-manifest-digest": "sha256:3b2c249b772868bcfba7e4389dffe22fe5a7074c2d4b3cff777e860aacf76fbc"
                    },
                    "type": "cosign container image signature"
                  },
                  "optional": null
                },
                "verified": true
              },
              {
                "payload": {
                  "critical": {
                    "identity": {
                      "docker-reference": "my-registry/foobar"
                    },
                    "image": {
                      "docker-manifest-digest": "sha256:3b2c249b772868bcfba7e4389dffe22fe5a7074c2d4b3cff777e860aacf76fbc"
                    },
                    "type": "cosign container image signature"
                  },
                  "optional": null
                },
                "verified": false
              }
            ]
          }
        }
      ]
    }
  }
  ```
</details>
