# golang-whois-lib

golang-whois-lib is light golang module for checking domain's whois without using hardcoded domain zones. Lib searching whois info also on reffered servers. And caching result for every zones into map.

## Installation

    go get github.com/Amonsat/golang-whois-lib

## Importing

    import (
        whois "github.com/Amonsat/golang-whois-lib"
    )

## How to use

    func GetWhois(domain string) (result string, err error)

    func GetWhoisTimeout(domain string, timeout time.Duration) (result string, err error)

## Example

    result, err := whois.GetWhois("google.com")
    if err != nil {

        fmt.Println(result)

        fmt.Printf("Nameservers: %v \n",whois.ParseNameServers(result))
    }

## LICENSE

Copyright 2017, Amonsat

Apache License, Version 2.0