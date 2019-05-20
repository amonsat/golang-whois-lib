# golang-whois-lib

golang-whois-lib is light golang module for checking domain's whois without using hardcoded domain zones. Lib searching whois info also on reffered servers. And caching result for every zones into map.

## Installation

```go
    go get github.com/amonsat/golang-whois-lib
```

## Importing

```go
    import (
        whois "github.com/amonsat/golang-whois-lib"
    )
```

## How to use

```go
    func GetWhois(domain string) (result string, err error)

    func GetWhoisTimeout(domain string, timeout time.Duration) (result string, err error)
```

## Example

```go
    result, _ := whois.GetWhois("google.com")

    fmt.Println(result)
    fmt.Printf("Nameservers: %v \n",whois.ParseNameServers(result))
```

## LICENSE

Copyright 2017, Amonsat

Apache License, Version 2.0