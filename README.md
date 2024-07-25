# 👮‍♀️ AuthZ

[![Test & Build](https://github.com/zeiss/fiber-authz/actions/workflows/main.yml/badge.svg)](https://github.com/zeiss/fiber-authz/actions/workflows/main.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/zeiss/fiber-authz.svg)](https://pkg.go.dev/github.com/zeiss/fiber-authz)
[![Go Report Card](https://goreportcard.com/badge/github.com/zeiss/fiber-authz)](https://goreportcard.com/report/github.com/zeiss/fiber-authz)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Taylor Swift](https://img.shields.io/badge/secured%20by-taylor%20swift-brightgreen.svg)](https://twitter.com/SwiftOnSecurity)

## Installation

```bash
$ go get github.com/zeiss/fiber-authz
```

## Usage

- [x] [OpenFGA](https://openfga.dev/)
- [x] Team-based access control
- [x] Role-based access control
- [x] Noop (for testing)

Any authorization model can be implemented by implementing the `Authorizer` interface.

## OpenAPI

Using [OpenAPI Extensions](https://swagger.io/docs/specification/openapi-extensions/) individual operations can be protected with [OpenFGA](https://openfga.dev/).

```yaml
x-fiber-authz-fga:
  user:
    namespace: user
    auth_type: oidc
  relation:
    name: admin
  object:
    namespace: system
    components:
      - in: params
        name: teamId
```

There are three parts to the OpenAPI extension:

- `user` - The user namespace and authentication type.
- `relation` - The relation name.
- `object` - The object namespace and components.

Then there are components to construct the relation or object.

- `in` - The location of the component (e.g. `params`).
- `name` - The name of the component (e.g. `teamId`).
- `type` - The type of the component (e.g. `string`).

## Examples

See [examples](https://github.com/zeiss/fiber-authz/tree/master/examples) to understand the provided interfaces.

## License

[MIT](/LICENSE)
