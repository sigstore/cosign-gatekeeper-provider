# cosign-gatekeeper-provider
To integrate [OPA Gatekeeper's new ExternalData feature](https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata) with [cosign](https://github.com/sigstore/cosign) to determine whether the images are valid by verifying its signatures.

> This repo is meant for testing Gatekeeper external data feature. Do not use for production.

## Installation

- Deploy Gatekeeper with external data enabled (`--enable-external-data`)
```sh
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper/gatekeeper  \
    --name-template=gatekeeper \
    --namespace gatekeeper-system --create-namespace \
    --set enableExternalData=true \
    --set controllerManager.dnsPolicy=ClusterFirst,audit.dnsPolicy=ClusterFirst \
    --version 3.10.0
```
_Note: This repository is currently only working with Gatekeeper 3.10 and the `externalData` feature in `alpha`. There is an open issue to track the support of Gatekeeper 3.11 and `externalData` feature in `beta`: https://github.com/sigstore/cosign-gatekeeper-provider/issues/20._

Let's install the `cosign-gatekeeper-provider`:

- `kubectl apply -f manifest`

- `kubectl apply -f manifest/provider.yaml`
  > Update `url` if it's not `http://cosign-gatekeeper-provider.cosign-gatekeeper-provider:8090` (default)

- `kubectl apply -f policy/template.yaml`

- `kubectl apply -f policy/constraint.yaml`

## Verification

To test this successfully, we should sign one of our images with [cosign](https://github.com/sigstore/cosign#installation) tool. So, let's do this first:

Generate key pair
```shell
$ cosign generate-key-pair
```

We have two files under `policy/examples`, one for valid manifest that contains signed image, the other is invalid. To do the same you should sign your image as I did:

```shell
$ crane copy alpine:latest devopps/alpine:signed
$ crane copy alpine:3.14 devopps/alpine:unsigned
$ cosign sign --key cosign.key devopps/signed:latest
```

So, once you are ready, let's apply these manifests one by one. It should allow deploying Pod for valid.yaml, and deny for the other one.

## Configuration

The provider can be configured with a configuration file passed with the
`-config-file=<file>` flag.

The verification options for specific image references can be configured by
defining verifiers for an image reference or image reference pattern. The
validator iterates over the list of `imageVerifiers` and uses the first
matching item.

If a matching item can't be found then it will return an error for that image
in the response.

```yaml
imageVerifiers:
  # Verify images in the my-project GCR registry with GCP KMS and the rekor
  # server
  - image: "eu.gcr.io/my-project/*"
    verifiers:
      - options:
          key: "gcpkms://projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key"
      - options:
          rekorURL: "https://rekor.sigstore.dev"

  # Verify images from my-registry with /cosign.pub
  - image: "my-registry:12345/*"
    verifiers:
      - options:
          key: "/cosign.pub"

  # Verify any other image with the rekor server
  - image: "*"
    verifiers:
      - options:
          rekorURL: "https://rekor.sigstore.dev"
```
