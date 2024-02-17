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

## Examples

See [examples](https://github.com/zeiss/fiber-authz/tree/master/examples) to understand the provided interfaces.

## License

[MIT](/LICENSE)
